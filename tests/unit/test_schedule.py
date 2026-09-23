"""P7 scheduling: cron/at/every -> launchd, next fires, plist, crontab, _fire."""

import json
import os
import plistlib
import stat
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest
from agentbox import cli, schedule
from agentbox.schedule import ScheduleError


# ---------------------------------------------------------------- translation
@pytest.mark.parametrize(
    "expr,want",
    [
        ("0 7 * * *", [{"Minute": 0, "Hour": 7}]),
        ("30 6 * * 1-5", [{"Minute": 30, "Hour": 6, "Weekday": d} for d in range(1, 6)]),
        ("0 7 * * mon-fri", [{"Minute": 0, "Hour": 7, "Weekday": d} for d in range(1, 6)]),
        ("0 9 1 * *", [{"Minute": 0, "Hour": 9, "Day": 1}]),
        ("0 9 * jan,jul *", [{"Minute": 0, "Hour": 9, "Month": m} for m in (1, 7)]),
        ("0 12 * * 7", [{"Minute": 0, "Hour": 12, "Weekday": 0}]),
        ("*/15 * * * *", [{"Minute": m} for m in (0, 15, 30, 45)]),
        ("0 */6 * * *", [{"Minute": 0, "Hour": h} for h in (0, 6, 12, 18)]),
        ("5 * * * *", [{"Minute": 5}]),
        ("10-20/5 3 * * *", [{"Minute": m, "Hour": 3} for m in (10, 15, 20)]),
        ("0 8 * * 0-7", [{"Minute": 0, "Hour": 8}]),  # 0-7 = every day
        # dom and dow both restricted: cron OR -> separate Day and Weekday entries
        ("0 8 15 * 1", [{"Minute": 0, "Hour": 8, "Day": 15},
                        {"Minute": 0, "Hour": 8, "Weekday": 1}]),
    ],
)  # fmt: skip
def test_launchd_calendar(expr, want):
    assert schedule.launchd_calendar(expr) == want


@pytest.mark.parametrize(
    "expr,msg",
    [
        ("@daily", "macros"),
        ("0 7 * *", "5 fields"),
        ("0 7 * * * *", "5 fields"),
        ("* * * * *", "--every 1m"),
        ("*/2 */2 * * 1-5", "limit 500"),  # 30 * 12 * 5 = 1800 entries
        ("0 7 L * *", "not supported"),
        ("0 7 15W * *", "not supported"),
        ("0 7 * * 5#3", "not supported"),
        ("0 7 ? * *", "not supported"),
        ("60 7 * * *", "outside"),
        ("0 24 * * *", "outside"),
        ("0 7 0 * *", "outside"),
        ("0 7 * 13 *", "outside"),
        ("0 7 * * 8", "outside"),
        ("0 7 * * foo", "not a number"),
        ("5-1 7 * * *", "outside"),
        ("*/0 7 * * *", "step"),
    ],
)
def test_cron_refusals(expr, msg):
    with pytest.raises(ScheduleError, match=msg):
        schedule.launchd_calendar(expr)


def test_at_and_days_and_every():
    assert schedule.at_to_cron("07:05", None) == "5 7 * * *"
    assert schedule.at_to_cron("7:30", "mon-fri") == "30 7 * * 1,2,3,4,5"
    assert schedule.at_to_cron("23:59", "sat-sun") == "59 23 * * 6,0"
    assert schedule.at_to_cron("08:00", "mon,wed,fri") == "0 8 * * 1,3,5"
    assert schedule.launchd_calendar(schedule.at_to_cron("23:59", "sat-sun")) == [
        {"Minute": 59, "Hour": 23, "Weekday": 0},
        {"Minute": 59, "Hour": 23, "Weekday": 6},
    ]
    for bad in ("24:00", "7", "07:60", "ab:cd"):
        with pytest.raises(ScheduleError, match="HH:MM"):
            schedule.at_to_cron(bad, None)
    with pytest.raises(ScheduleError, match="--days"):
        schedule.at_to_cron("07:00", "weekday")
    assert schedule.parse_every("30m") == 1800
    assert schedule.parse_every("2h") == 7200
    assert schedule.parse_every("1d") == 86400
    for bad in ("0m", "30", "1w", "1.5h", "-1m"):
        with pytest.raises(ScheduleError):
            schedule.parse_every(bad)


def test_make_spec_rules():
    with pytest.raises(ScheduleError, match="exactly one"):
        schedule.make_spec("0 7 * * *", "1h", None, None)
    with pytest.raises(ScheduleError, match="exactly one"):
        schedule.make_spec(None, None, None, None)
    with pytest.raises(ScheduleError, match="only with --at"):
        schedule.make_spec(None, "1h", None, "mon-fri")
    assert schedule.make_spec(None, None, "07:00", "mon-fri").cron == "0 7 * * 1,2,3,4,5"
    assert schedule.make_spec("0  7 * *  *", None, None, None).cron == "0 7 * * *"


# ---------------------------------------------------------------- next fires
def test_next_fires():
    now = datetime(2026, 9, 23, 7, 0, 30)  # a Wednesday
    nf = schedule.next_fires(schedule.Spec(cron="0 7 * * 1-5"), now)
    assert nf == [datetime(2026, 9, 24, 7, 0), datetime(2026, 9, 25, 7, 0),
                  datetime(2026, 9, 28, 7, 0)]  # fmt: skip
    nf = schedule.next_fires(schedule.Spec(cron="*/20 7 * * *"), datetime(2026, 9, 23, 7, 5))
    assert nf == [datetime(2026, 9, 23, 7, 20), datetime(2026, 9, 23, 7, 40),
                  datetime(2026, 9, 24, 7, 0)]  # fmt: skip
    # dom OR dow: the 1st, or any Sunday
    nf = schedule.next_fires(schedule.Spec(cron="0 0 1 * 0"), datetime(2026, 9, 23))
    assert nf == [datetime(2026, 9, 27), datetime(2026, 10, 1), datetime(2026, 10, 4)]
    # leap day
    nf = schedule.next_fires(schedule.Spec(cron="0 0 29 2 *"), datetime(2026, 9, 23), 1)
    assert nf == [datetime(2028, 2, 29)]
    nf = schedule.next_fires(schedule.Spec(every=1800), datetime(2026, 9, 23, 7, 0, 10))
    assert nf == [datetime(2026, 9, 23, 7, 30), datetime(2026, 9, 23, 8, 0),
                  datetime(2026, 9, 23, 8, 30)]  # fmt: skip


# ---------------------------------------------------------------- plist
SECRET = "sk-ant-oat01-SECRETVALUE-should-never-appear"


@pytest.fixture
def roots(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.setenv("AGENTBOX_LAUNCHAGENTS_DIR", str(tmp_path / "la"))
    monkeypatch.setenv("AGENTBOX_LAUNCHD_PREFIX", "com.agentbox-unit")
    store = tmp_path / "store.json"
    store.write_text(json.dumps({"AGENTBOX__SHARED_CLAUDE_CODE_OAUTH_TOKEN": SECRET}))
    monkeypatch.setenv("AGENTBOX_TEST_SECRET_STORE", str(store))
    monkeypatch.setenv("CLAUDE_CODE_OAUTH_TOKEN", SECRET)
    monkeypatch.setenv("SOME_API_KEY", SECRET)
    return tmp_path


def make_job(tmp_path, spec, profile="p1", name="daily"):
    prog, extra = schedule.program_args(argv0="")
    jd = schedule.job_dir(profile, name)
    jd.mkdir(parents=True, exist_ok=True)
    label = schedule.label_for(profile, name)
    job = {
        "profile": profile, "name": name, "agent": "claude", "model": None,
        "schedule": spec.as_json(), "dir": str(jd), "label": label,
        "plist": str(schedule.launchagents_dir() / f"{label}.plist"),
        "argv": schedule.fire_argv(prog, profile, name), "env": schedule.job_env(extra),
    }  # fmt: skip
    (jd / "job.json").write_text(json.dumps(job))
    (jd / "prompt.md").write_text("hello\n")
    return job


def test_plist_render(roots):
    job = make_job(roots, schedule.Spec(cron="0 7 * * 1-5"))
    d = schedule.render_plist(job)
    assert d["Label"] == "com.agentbox-unit.p1.daily"
    assert all(os.path.isabs(a) for a in d["ProgramArguments"][:1])
    assert d["ProgramArguments"][-4:] == ["schedule", "_fire", "p1", "daily"]
    assert d["RunAtLoad"] is False and "StartInterval" not in d
    assert len(d["StartCalendarInterval"]) == 5
    env = d["EnvironmentVariables"]
    assert set(env) >= {"PATH", "HOME", "AGENTBOX_STATE_HOME", "AGENTBOX_CONFIG_HOME"}
    dirs = env["PATH"].split(":")
    assert all(os.path.isabs(x) for x in dirs)
    assert os.path.dirname(os.path.abspath(__import__("shutil").which("docker"))) in dirs
    assert schedule.DOCKER_APP_BIN in dirs
    assert d["StandardOutPath"] == str(Path(job["dir"]) / "launchd.out")
    assert d["StandardErrorPath"] == str(Path(job["dir"]) / "launchd.err")
    for k, v in env.items():
        assert os.path.isabs(v) or k not in ("HOME",)
    raw = plistlib.dumps(d)
    assert SECRET.encode() not in raw
    assert b"CLAUDE_CODE_OAUTH_TOKEN" not in raw and b"SOME_API_KEY" not in raw
    assert plistlib.loads(raw) == d
    job2 = make_job(roots, schedule.Spec(every=1800), name="half")
    d2 = schedule.render_plist(job2)
    assert d2["StartInterval"] == 1800 and "StartCalendarInterval" not in d2


def test_program_args_fallback_and_installed(tmp_path, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    prog, extra = schedule.program_args(argv0="/x/cli.py")
    assert os.path.isabs(prog[0]) and prog[1:] == ["-m", "agentbox.cli"]
    assert Path(extra["PYTHONPATH"], "agentbox", "cli.py").is_file()
    exe = tmp_path / "agentbox"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)
    assert schedule.program_args(argv0=str(exe)) == ([str(exe)], {})
    monkeypatch.setenv("PATH", f"{tmp_path}:/usr/bin")
    assert schedule.program_args(argv0="/x/cli.py") == ([str(exe)], {})


def test_job_env_needs_docker(monkeypatch):
    monkeypatch.setenv("PATH", "/nonexistent")
    with pytest.raises(ScheduleError, match="docker is not on PATH"):
        schedule.job_env()


# ---------------------------------------------------------------- crontab
def test_crontab_add_remove_idempotent(roots):
    job = make_job(roots, schedule.Spec(cron="0 7 * * 1-5"))
    line = schedule.cron_line(job)
    assert line.startswith("0 7 * * 1-5 cd / && PATH=")
    assert "schedule _fire p1 daily" in line and SECRET not in line
    user = "MAILTO=me\n0 1 * * * /usr/bin/backup\n"
    t1 = schedule.crontab_set(user, "p1", "daily", line)
    t2 = schedule.crontab_set(t1, "p1", "daily", line)
    assert t1 == t2 and t1.count("# agentbox:p1:daily") == 1
    t3 = schedule.crontab_set(t2, "p1", "other", line)
    assert t3.count("# agentbox:") == 2
    back = schedule.crontab_remove(schedule.crontab_remove(t3, "p1", "other"), "p1", "daily")
    assert back == user
    assert schedule.crontab_remove(back, "p1", "daily") == user
    assert schedule.crontab_remove("", "p1", "daily") == ""
    assert schedule.every_to_cron(1800) == "*/30 * * * *"
    assert schedule.every_to_cron(7200) == "0 */2 * * *"
    assert schedule.every_to_cron(86400) == "0 0 * * *"
    for bad in (7 * 60, 5 * 3600, 2 * 86400):
        with pytest.raises(ScheduleError, match="no exact cron form"):
            schedule.every_to_cron(bad)


# ---------------------------------------------------------------- _fire
def fake_bin(d: Path, name: str, body: str) -> None:
    d.mkdir(exist_ok=True)
    f = d / name
    f.write_text("#!/bin/sh\n" + body)
    f.chmod(f.stat().st_mode | stat.S_IXUSR)


def ok_preflight(profile, agent, model=None, code=()):
    return None, []


def test_fire_success_last_json(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    rd = roots / "run1"
    rd.mkdir()
    seen = {}

    def runner(profile, agent, prompt, model, timeout):
        seen.update(timeout=timeout, profile=profile, agent=agent, prompt=Path(prompt).read_text())
        return 3, rd

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 3
    assert seen == {"profile": "p1", "agent": "claude", "prompt": "hello\n", "timeout": 7200}
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["status"] == "failed" and last["exit_code"] == 3
    assert last["run_dir"] == str(rd) and last["transcript"] == str(rd / "transcript.log")
    assert last["start"] and last["end"] and last["message"] is None
    assert (Path(job["dir"]) / "last.json").stat().st_mode & 0o777 == 0o600
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    assert json.loads((Path(job["dir"]) / "last.json").read_text())["status"] == "ok"
    hist = (Path(job["dir"]) / "history.jsonl").read_text().splitlines()
    assert [json.loads(x)["exit_code"] for x in hist] == [3, 0]


def test_fire_preflight_failure_recorded(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))

    def runner(*a):
        raise AssertionError("must not run")

    fix = "CLAUDE_CODE_OAUTH_TOKEN is missing: run `agentbox setup`"
    rc = schedule.fire("p1", "daily", runner, lambda p, a, m, c: (fix, ["MYTOK missing"]))
    assert rc == schedule.RC_PREFLIGHT
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["status"] == "failed" and last["message"] == fix
    assert last["warnings"] == ["MYTOK missing"]


def test_fire_runner_exception_recorded(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))

    def runner(*a):
        raise cli.RunFailed("box start failed", roots / "rdx")

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 125
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["run_dir"] == str(roots / "rdx") and "box start failed" in last["message"]


def test_fire_docker_down(roots, monkeypatch, capsys):
    """docker info always fails; `open -ga Docker` is called; clear log line; no run."""
    bind = roots / "bin"
    fake_bin(bind, "docker", "exit 1\n")
    fake_bin(bind, "open", f'echo "$@" >> {roots / "open.log"}\n')
    monkeypatch.setenv("PATH", f"{bind}:/usr/bin:/bin")
    monkeypatch.setattr(schedule, "is_macos", lambda: True)
    job = make_job(roots, schedule.Spec(every=60))

    def runner(*a):
        raise AssertionError("must not run")

    rc = schedule.fire("p1", "daily", runner, ok_preflight, wait=0.5, poll=0.1)
    assert rc == schedule.RC_DOCKER_DOWN
    assert (roots / "open.log").read_text().split() == ["-ga", "Docker"]
    err = capsys.readouterr().err
    assert "starting Docker Desktop" in err and "Docker did not come up within" in err
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["status"] == "failed" and last["exit_code"] == schedule.RC_DOCKER_DOWN
    assert "schedule run-now p1 daily" in last["message"]


def test_fire_docker_comes_up(roots, monkeypatch):
    """docker info fails until `open` ran; then the job runs."""
    bind = roots / "bin"
    flag = roots / "started"
    fake_bin(bind, "docker", f"[ -f {flag} ] && exit 0; exit 1\n")
    fake_bin(bind, "open", f"touch {flag}\n")
    monkeypatch.setenv("PATH", f"{bind}:/usr/bin:/bin")
    monkeypatch.setattr(schedule, "is_macos", lambda: True)
    make_job(roots, schedule.Spec(every=60))
    rc = schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight, wait=5, poll=0.1)
    assert rc == 0


def test_fire_overlap_skips(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    started, release = threading.Event(), threading.Event()

    def slow(*a):
        started.set()
        release.wait(10)
        return 0, roots / "rd"

    rcs = {}
    t = threading.Thread(
        target=lambda: rcs.setdefault("a", schedule.fire("p1", "daily", slow, ok_preflight))
    )
    t.start()
    assert started.wait(10)
    rcs["b"] = schedule.fire(
        "p1", "daily", lambda *a: (_ for _ in ()).throw(AssertionError), ok_preflight
    )
    release.set()
    t.join(10)
    assert rcs == {"a": 0, "b": schedule.RC_SKIPPED}
    jd = Path(job["dir"])
    hist = [json.loads(x) for x in (jd / "history.jsonl").read_text().splitlines()]
    assert [h["status"] for h in hist] == ["skipped", "ok"]
    assert hist[0]["message"] == "skipped: a run is active"
    assert schedule.skip_summary(jd) is None  # the last entry is a real run
    assert json.loads((jd / "last.json").read_text())["status"] == "ok"
    assert json.loads((jd / "skipped.json").read_text())["status"] == "skipped"


# ---------------------------------------------------------------- CLI flows (no launchctl)
PROFILE = """
[box]
agents = ["claude", "codex"]

[[mount]]
host = "{mount}"
mode = "rw"
allow_dotpath = true

[models]
ollama = "local"

[secrets]
MYTOK = {{}}
"""


@pytest.fixture
def cli_env(roots, monkeypatch):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    monkeypatch.setattr("agentbox.box.mountstate.symlink_problems", lambda p: [])
    (roots / "cfg" / "profiles").mkdir(parents=True)
    (roots / "cfg" / "config.toml").write_text(
        'secret_backend = "env"\nsecret_prefix = "agentbox"\n'
    )
    (roots / "cfg" / "profiles" / "p1.toml").write_text(PROFILE.format(mount=roots))
    calls = []
    monkeypatch.setattr(schedule, "launchctl", lambda *a: calls.append(a) or _cp(1))
    monkeypatch.setattr(schedule, "is_macos", lambda: True)
    (roots / "prompt.txt").write_text("do the thing\n")
    return calls


def _cp(rc):
    import subprocess

    return subprocess.CompletedProcess([], rc, "", "")


def test_cli_add_ls_rm(roots, cli_env, capsys, monkeypatch):
    pf = str(roots / "prompt.txt")
    args = ["schedule", "add", "p1", "--name", "morning", "--agent", "claude", "--prompt-file", pf]

    # bootstrap "fails" (rc 1 from the fake) -> error; make it succeed instead
    def fake(*a):
        cli_env.append(a)
        return _cp(1 if a[0] == "print" else 0)

    monkeypatch.setattr(schedule, "launchctl", fake)
    assert cli.main([*args, "--at", "07:00", "--days", "mon-fri"]) == 0
    out = capsys.readouterr()
    assert out.out.count("\n  20") == 3  # three next fire times
    assert "agentbox schedule run-now p1 morning" in out.out
    assert "CLAUDE_CODE_OAUTH_TOKEN is missing" not in out.err  # stored in the env store
    plist = roots / "la" / "com.agentbox-unit.p1.morning.plist"
    d = plistlib.loads(plist.read_bytes())
    assert len(d["StartCalendarInterval"]) == 5 and SECRET.encode() not in plist.read_bytes()
    assert ("bootstrap", f"gui/{os.getuid()}", str(plist)) in cli_env
    jd = schedule.job_dir("p1", "morning")
    assert (jd / "prompt.md").read_text() == "do the thing\n"
    assert (jd / "prompt.md").stat().st_mode & 0o777 == 0o600
    # duplicate refused; --force replaces the prompt
    assert cli.main([*args, "--every", "1h"]) == 1
    assert "--force" in capsys.readouterr().err
    (roots / "prompt.txt").write_text("v2\n")
    assert cli.main([*args, "--every", "1h", "--force"]) == 0
    assert (jd / "prompt.md").read_text() == "v2\n"
    assert plistlib.loads(plist.read_bytes())["StartInterval"] == 3600
    capsys.readouterr()
    assert cli.main(["schedule", "ls"]) == 0
    out = capsys.readouterr().out
    assert "p1/morning" in out and "every 1h" in out and "last: never" in out
    assert cli.main(["schedule", "rm", "p1", "morning"]) == 0
    assert not plist.exists() and not jd.exists()
    assert cli.main(["schedule", "rm", "p1", "morning"]) == 1


def test_cli_add_refusals(roots, cli_env, capsys):
    pf = str(roots / "prompt.txt")
    base = ["schedule", "add", "p1", "--prompt-file", pf]
    assert cli.main([*base, "--name", "Bad_Name", "--agent", "claude", "--every", "1h"]) == 1
    assert cli.main([*base, "--name", "x", "--agent", "pi", "--every", "1h"]) == 1
    assert "not in [box] agents" in capsys.readouterr().err
    assert cli.main([*base, "--name", "x", "--agent", "claude", "--cron", "*/2 */2 * * 1-5"]) == 1
    assert "limit 500" in capsys.readouterr().err
    assert cli.main([*base, "--name", "x", "--agent", "claude"]) == 1
    assert not schedule.job_dir("p1", "x").exists()


def test_preflight_only_agent_credential(roots, cli_env, capsys, monkeypatch):
    """Reviewer repros: a codex job never fails on the Claude token; a claude
    job never fails on an unused missing secret (MYTOK): it is a warning."""
    (roots / "store.json").write_text("{}")
    monkeypatch.setattr(schedule, "launchctl",
                        lambda *a: _cp(1 if a[0] == "print" else 0))  # fmt: skip
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "codex", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    assert rc == 0
    err = capsys.readouterr().err
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in err
    assert "warning: MYTOK" in err and "agentbox login p1 codex" in err
    assert cli.sched_preflight("p1", "codex") == (None, [ANY_MYTOK])
    e, w = cli.sched_preflight("p1", "claude")
    assert e.startswith("CLAUDE_CODE_OAUTH_TOKEN is missing: run `agentbox setup`")
    assert w == [ANY_MYTOK]
    assert cli.sched_preflight("p1", "claude", "ollama/llama3") == (None, [ANY_MYTOK])
    assert cli.sched_preflight("p1", "pi") == ("pi is not in [box] agents of p1", [])
    (roots / "store.json").write_text(
        json.dumps({"AGENTBOX__SHARED_CLAUDE_CODE_OAUTH_TOKEN": SECRET})
    )
    assert cli.sched_preflight("p1", "claude") == (None, [ANY_MYTOK])


class _Mytok(str):
    def __eq__(self, other):
        return isinstance(other, str) and other.startswith("MYTOK (") and "secret set p1" in other

    __hash__ = str.__hash__


ANY_MYTOK = _Mytok("MYTOK")


def test_add_prints_env_names_and_fallback_warning(roots, cli_env, capsys, monkeypatch):
    monkeypatch.setattr(schedule, "launchctl",
                        lambda *a: _cp(1 if a[0] == "print" else 0))  # fmt: skip
    real = schedule.shutil.which
    monkeypatch.setattr(schedule.shutil, "which", lambda n: None if n == "agentbox" else real(n))
    monkeypatch.setattr(schedule.sys, "argv", ["/x/cli.py"])
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt"), "--timeout", "30m"])  # fmt: skip
    assert rc == 0
    out, err = capsys.readouterr()
    line = next(x for x in out.splitlines() if x.startswith("job environment:"))
    assert "AGENTBOX_STATE_HOME" in line and "PYTHONPATH" in line and "/" not in line
    assert "uv tool install -e ./cli" in err
    assert "timeout 30m" in out
    assert schedule.load_job("p1", "c")["timeout"] == 1800
    assert cli.main(["schedule", "edit", "p1", "c", "--timeout", "none"]) == 0
    assert schedule.load_job("p1", "c")["timeout"] is None
    assert cli.main(["schedule", "edit", "p1", "c"]) == 1


def test_add_render_failure_leaves_nothing(roots, cli_env, monkeypatch, capsys):
    def bad(job):
        raise ValueError("bad plist value")

    monkeypatch.setattr(schedule, "render_plist", bad)
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    assert rc == 1 and "cannot render" in capsys.readouterr().err
    assert not schedule.job_dir("p1", "c").exists() and not (roots / "la").exists()


def test_add_install_failure_leaves_no_job_dir(roots, cli_env, monkeypatch, capsys):
    monkeypatch.setattr(schedule, "launchctl",
                        lambda *a: _cp(1 if a[0] in ("print", "bootstrap") else 0))  # fmt: skip
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    assert rc == 1 and "bootstrap" in capsys.readouterr().err
    assert not schedule.job_dir("p1", "c").exists()
    assert not list((roots / "la").glob("*.plist"))


def test_add_refuses_never_firing_cron(roots, cli_env, capsys):
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude",
                   "--cron", "0 0 30 2 *", "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    assert rc == 1 and "never fires within a year" in capsys.readouterr().err


def test_add_warns_op_without_service_account(roots, cli_env, capsys, monkeypatch):
    monkeypatch.setattr(schedule, "launchctl",
                        lambda *a: _cp(1 if a[0] == "print" else 0))  # fmt: skip
    from agentbox import secretstore

    monkeypatch.setattr(secretstore, "exists", lambda ref, sa=None: False)
    monkeypatch.setattr(cli, "sched_check", lambda *a: (None, []))
    (roots / "cfg" / "config.toml").write_text(
        'secret_backend = "op"\nop_vault = "V"\nsecret_prefix = "agentbox"\n'
    )
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    assert rc == 0
    assert "cannot answer a 1Password prompt" in capsys.readouterr().err


@pytest.mark.parametrize(
    "argv",
    [["schedule", "edit", "p1", "Bad_N", "--timeout", "1h"], ["schedule", "run-now", "p1", "../x"],
     ["schedule", "ls", "Bad"], ["schedule", "_fire", "p1", "a/b"], ["schedule", "rm", "P", "x"]],
)  # fmt: skip
def test_names_validated_everywhere(roots, argv, capsys):
    assert cli.main(argv) == 1
    assert "must match" in capsys.readouterr().err


def test_fire_skip_rc_and_ls_summary(roots, cli_env, monkeypatch, capsys):
    import fcntl

    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    jd = Path(job["dir"])
    with (jd / "fire.lock").open("a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        assert schedule.fire("p1", "daily", None, ok_preflight) == 75
        assert schedule.fire("p1", "daily", None, ok_preflight) == 75
        assert not schedule.lock_free(jd)
    assert schedule.skip_summary(jd).startswith("skipped 2 since 20")
    # a last.json that says running while fire.lock is free: stale
    schedule.write_private(jd / "last.json", json.dumps({"status": "running"}).encode())
    capsys.readouterr()
    assert cli.main(["schedule", "ls", "p1"]) == 0
    out = capsys.readouterr().out
    assert "running (stale" in out and "skipped 2 since" in out


def test_fire_terminated_recorded(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))

    def runner(*a):
        raise cli.RunFailed("terminated by signal 15", roots / "rd", schedule.RC_TERMINATED)

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 143
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["status"] == "terminated" and last["exit_code"] == 143
    assert last["run_dir"] == str(roots / "rd")

    def during_wait(*a):
        raise schedule.Terminated(15)

    monkeypatch.setattr(schedule, "ensure_docker", during_wait)
    assert schedule.fire("p1", "daily", runner, ok_preflight) == 143
    hist = (Path(job["dir"]) / "history.jsonl").read_text().splitlines()
    assert [json.loads(x)["status"] for x in hist] == ["terminated", "terminated"]


def test_rotate(tmp_path):
    f = tmp_path / "launchd.err"
    f.write_bytes(b"x" * 11)
    schedule.rotate(f, limit=10)
    assert not f.exists() and (tmp_path / "launchd.err.1").read_bytes() == b"x" * 11
    f.write_bytes(b"y" * 5)
    schedule.rotate(f, limit=10)
    assert f.exists()


def test_label_prefix_validated(monkeypatch):
    monkeypatch.setenv("AGENTBOX_LAUNCHD_PREFIX", "bad prefix")
    with pytest.raises(ScheduleError):
        schedule.label_for("p", "n")


def test_write_private_mode(tmp_path):
    f = tmp_path / "a" / "b.json"
    schedule.write_private(f, b"x")
    assert f.stat().st_mode & 0o777 == 0o600
    time.sleep(0)


def test_fire_records_left_up(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    rd = roots / "rd"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps({"left_up": "other processes (sleep 99)"}))
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["left_up"] == "left up: other processes (sleep 99)"


def test_job_code_paths():
    job = {"argv": ["/py/bin/python3", "-m", "agentbox.cli"], "env": {"PYTHONPATH": "/a:/b"}}
    assert schedule.job_code_paths(job) == ("/py/bin/python3", "/a", "/b")


def test_add_refuses_rw_mount_over_job_code(roots, cli_env, monkeypatch, capsys):
    """The profile's rw mount (roots) contains the job's PYTHONPATH entry."""
    code = roots / "code"
    code.mkdir()
    monkeypatch.setattr(schedule, "program_args",
                        lambda argv0=None: (["/usr/bin/python3", "-m", "agentbox.cli"],
                                            {"PYTHONPATH": str(code)}))  # fmt: skip
    rc = cli.main(["schedule", "add", "p1", "--name", "c", "--agent", "claude", "--every", "1h",
                   "--prompt-file", str(roots / "prompt.txt")])  # fmt: skip
    err = capsys.readouterr().err
    assert rc == 1 and "overlaps" in err and "change what runs on the host" in err
    assert not schedule.job_dir("p1", "c").exists()
    msg, _ = cli.sched_preflight("p1", "claude", None, (str(code),))
    assert msg and "overlaps" in msg
