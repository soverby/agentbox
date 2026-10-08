"""P7 scheduling: cron/at/every -> launchd, next fires, plist, crontab, _fire."""

import hashlib
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
    # job_env needs a `docker` on PATH; unit tests must not need a real one.
    # Appended, so a test's own fake_bin dir placed first still wins.
    fake_bin(tmp_path / "sysbin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", os.environ["PATH"] + os.pathsep + str(tmp_path / "sysbin"))
    return tmp_path


def make_job(tmp_path, spec, profile="p1", name="daily", kind=None):
    """kind None: a job.json from before command jobs (no `kind` field)."""
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
    if kind is not None:
        job["kind"] = kind
    if kind == "cmd":
        job["agent"] = None
    (jd / "job.json").write_text(json.dumps(job))
    (jd / schedule.job_file(schedule.job_kind(job))).write_text("hello\n")
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


def test_fire_records_stopped_leftovers(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    rd = roots / "rd"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps({"stopped": "killed leftover processes (sleep 9)"}))
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["stopped"] == "stopped: killed leftover processes (sleep 9)"
    assert "left_up" not in last


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


def test_fire_records_host_config_changes(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    rd = roots / "rd"
    rd.mkdir()
    (rd / "meta.json").write_text(json.dumps({"host_config_changes": ["m: .envrc: added: x"]}))
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["host_config_changes"] == ["m: .envrc: added: x"]


# ---------------------------------------------------------------- command jobs
def test_job_kind_and_file():
    assert schedule.job_kind({"agent": "claude"}) == "agent"  # job.json from before kinds
    assert schedule.job_kind({"kind": "agent"}) == "agent"
    assert schedule.job_kind({"kind": "cmd"}) == "cmd"
    assert schedule.job_file("agent") == "prompt.md" and schedule.job_file("cmd") == "command.sh"
    with pytest.raises(ScheduleError, match="unknown kind 'bash'"):
        schedule.job_kind({"profile": "p", "name": "n", "kind": "bash"})


def test_fire_legacy_job_runs_as_agent(roots, monkeypatch):
    """A job.json without `kind` keeps working: agent job, prompt.md, agent preflight."""
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    assert "kind" not in json.loads((Path(job["dir"]) / "job.json").read_text())
    seen = {}

    def runner(profile, agent, prompt, model, timeout):
        seen["run"] = (agent, Path(prompt).name, Path(prompt).read_text())
        return 0, roots

    def preflight(profile, agent, model=None, code=()):
        seen["pre"] = agent
        return None, []

    assert schedule.fire("p1", "daily", runner, preflight) == 0
    assert seen == {"run": ("claude", "prompt.md", "hello\n"), "pre": "claude"}
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["kind"] == "agent" and last["agent"] == "claude"


def test_fire_cmd_job(roots, monkeypatch):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60), kind="cmd")
    seen = {}

    def runner(profile, agent, prompt, model, timeout):
        seen["run"] = (agent, Path(prompt).name, Path(prompt).read_text(), model, timeout)
        return 124, roots

    def preflight(profile, agent, model=None, code=()):
        seen["pre"] = (agent, model)
        return None, []

    assert schedule.fire("p1", "daily", runner, preflight) == 124
    assert seen == {"run": (None, "command.sh", "hello\n", None, 7200), "pre": (None, None)}
    last = json.loads((Path(job["dir"]) / "last.json").read_text())
    assert last["kind"] == "cmd" and last["agent"] is None and last["exit_code"] == 124
    assert "killed after the timeout" in last["message"]


def test_fire_unknown_kind_is_a_hard_error(roots):
    job = make_job(roots, schedule.Spec(every=60), kind="cmd")
    f = Path(job["dir"]) / "job.json"
    f.write_text(json.dumps({**job, "kind": "weird"}))
    with pytest.raises(ScheduleError, match="unknown kind"):
        schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight)


def test_sched_runner_passes_command_job_through(roots, cli_env, monkeypatch):
    got = {}

    def fake(b, agent, prompt_file, model, host_dir, made=None, timeout=None):
        got.update(agent=agent, file=prompt_file, model=model, dir=host_dir, timeout=timeout)
        return 0, roots

    monkeypatch.setattr(cli, "run_headless", fake)
    assert cli.sched_runner("p1", None, "/x/command.sh", None, 60) == (0, roots)
    assert got == {"agent": None, "file": Path("/x/command.sh"), "model": None, "dir": "/",
                   "timeout": 60}  # fmt: skip


def add_cmd(roots, *extra, name="fx", profile="p1"):
    return cli.main(["schedule", "add", profile, "--name", name, "--cmd-file",
                     str(roots / "fx.sh"), *extra])  # fmt: skip


@pytest.fixture
def cmd_env(roots, cli_env, monkeypatch):
    monkeypatch.setattr(schedule, "launchctl",
                        lambda *a: _cp(1 if a[0] == "print" else 0))  # fmt: skip
    (roots / "fx.sh").write_text("curl -s example.com | python3 -c 'pass'\n")
    # a profile whose [box] agents has neither claude nor codex: a command job still works
    (roots / "cfg" / "profiles" / "p2.toml").write_text(
        PROFILE.format(mount=roots).replace('agents = ["claude", "codex"]', 'agents = ["pi"]')
    )
    return cli_env


def test_cli_add_cmd_job_ls_rm(roots, cmd_env, capsys):
    assert add_cmd(roots, "--at", "06:30", "--timeout", "10m", profile="p2") == 0
    out = capsys.readouterr()
    assert (
        "p2/fx" in out.out and "timeout 10m" in out.out and "agentbox schedule run-now" in out.out
    )
    jd = schedule.job_dir("p2", "fx")
    job = json.loads((jd / "job.json").read_text())
    assert job["kind"] == "cmd" and job["agent"] is None and job["model"] is None
    assert job["timeout"] == 600
    assert (jd / "command.sh").read_text() == "curl -s example.com | python3 -c 'pass'\n"
    assert (jd / "command.sh").stat().st_mode & 0o777 == 0o600
    assert not (jd / "prompt.md").exists()
    assert SECRET.encode() not in (jd / "job.json").read_bytes()
    assert cli.main(["schedule", "ls"]) == 0
    ls = capsys.readouterr().out
    line = next(x for x in ls.splitlines() if x.startswith("p2/fx"))
    assert "kind=cmd" in line and "agent=" not in line and "cron 30 6 * * *" in line
    assert cli.main(["schedule", "rm", "p2", "fx"]) == 0 and not jd.exists()


def test_cli_ls_shows_kind_for_both(roots, cmd_env, capsys):
    pf = str(roots / "prompt.txt")
    assert cli.main(["schedule", "add", "p1", "--name", "a", "--agent", "claude",
                     "--prompt-file", pf, "--every", "1h"]) == 0  # fmt: skip
    assert add_cmd(roots, "--every", "2h") == 0
    # and a job.json from before kinds
    make_job(roots, schedule.Spec(every=60), name="old")
    capsys.readouterr()
    assert cli.main(["schedule", "ls", "p1"]) == 0
    lines = {x.split()[0]: x for x in capsys.readouterr().out.splitlines() if x.startswith("p1/")}
    assert "agent=claude" in lines["p1/a"] and "kind=cmd" in lines["p1/fx"]
    assert "agent=claude" in lines["p1/old"] and "kind=" not in lines["p1/old"]


@pytest.mark.parametrize(
    "extra,msg",
    [
        (["--agent", "claude"], "cannot be combined"),
        (["--prompt-file", "{p}"], "cannot be combined"),
        (["--model", "ollama/x"], "--model is not valid with --cmd-file"),
    ],
)
def test_cli_add_cmd_bad_combinations(roots, cmd_env, capsys, extra, msg):
    extra = [x.format(p=roots / "prompt.txt") for x in extra]
    assert add_cmd(roots, "--every", "1h", *extra) == 1
    assert msg in capsys.readouterr().err
    assert not schedule.job_dir("p1", "fx").exists()


def test_cli_add_needs_agent_or_cmd(roots, cmd_env, capsys):
    pf = str(roots / "prompt.txt")
    for extra in ([], ["--agent", "claude"], ["--prompt-file", pf]):
        assert cli.main(["schedule", "add", "p1", "--name", "x", "--every", "1h", *extra]) == 1
        assert "give --agent and --prompt-file (agent run) or --cmd-file" in capsys.readouterr().err
    assert not schedule.job_dir("p1", "x").exists()


def test_cli_add_cmd_missing_file(roots, cmd_env, capsys):
    (roots / "fx.sh").unlink()
    assert add_cmd(roots, "--every", "1h") == 1
    assert "cannot read command file" in capsys.readouterr().err
    assert not schedule.job_dir("p1", "fx").exists()


def test_cli_add_cmd_still_refuses_rw_mount_over_job_code(roots, cmd_env, monkeypatch, capsys):
    code = roots / "code"
    code.mkdir()
    monkeypatch.setattr(schedule, "program_args",
                        lambda argv0=None: (["/usr/bin/python3", "-m", "agentbox.cli"],
                                            {"PYTHONPATH": str(code)}))  # fmt: skip
    assert add_cmd(roots, "--every", "1h") == 1
    assert "overlaps" in capsys.readouterr().err
    assert not schedule.job_dir("p1", "fx").exists()


def test_cli_force_switches_kind_and_drops_stale_file(roots, cmd_env, capsys):
    pf = str(roots / "prompt.txt")
    base = ["schedule", "add", "p1", "--name", "x", "--every", "1h", "--force"]
    assert cli.main([*base, "--agent", "claude", "--prompt-file", pf]) == 0
    jd = schedule.job_dir("p1", "x")
    assert (jd / "prompt.md").is_file()
    assert cli.main([*base, "--cmd-file", str(roots / "fx.sh")]) == 0
    assert (jd / "command.sh").is_file() and not (jd / "prompt.md").exists()
    assert schedule.job_kind(schedule.load_job("p1", "x")) == "cmd"
    assert cli.main([*base, "--agent", "claude", "--prompt-file", pf]) == 0
    assert (jd / "prompt.md").is_file() and not (jd / "command.sh").exists()
    job = schedule.load_job("p1", "x")
    assert job["kind"] == "agent" and job["agent"] == "claude"


def test_cli_edit_rules(roots, cmd_env, capsys):
    pf = str(roots / "prompt.txt")
    assert add_cmd(roots, "--every", "1h") == 0
    assert cli.main(["schedule", "add", "p1", "--name", "a", "--agent", "claude",
                     "--prompt-file", pf, "--every", "1h"]) == 0  # fmt: skip
    capsys.readouterr()
    cmd_jd, agent_jd = schedule.job_dir("p1", "fx"), schedule.job_dir("p1", "a")
    (roots / "fx2.sh").write_text("echo v2\n")
    (roots / "prompt.txt").write_text("v2\n")
    # command job: --cmd-file replaces command.sh; --prompt-file is refused
    assert cli.main(["schedule", "edit", "p1", "fx", "--cmd-file", str(roots / "fx2.sh")]) == 0
    assert "command replaced" in capsys.readouterr().out
    assert (cmd_jd / "command.sh").read_text() == "echo v2\n"
    assert (cmd_jd / "command.sh").stat().st_mode & 0o777 == 0o600
    assert cli.main(["schedule", "edit", "p1", "fx", "--prompt-file", pf]) == 1
    assert "is a command job: use --cmd-file" in capsys.readouterr().err
    assert not (cmd_jd / "prompt.md").exists()
    # agent job: the reverse
    assert cli.main(["schedule", "edit", "p1", "a", "--cmd-file", str(roots / "fx2.sh")]) == 1
    assert "is an agent job: use --prompt-file" in capsys.readouterr().err
    assert not (agent_jd / "command.sh").exists()
    assert cli.main(["schedule", "edit", "p1", "a", "--prompt-file", pf]) == 0
    assert (agent_jd / "prompt.md").read_text() == "v2\n"
    # a refused edit changes nothing, even with a valid --timeout
    assert cli.main(["schedule", "edit", "p1", "a", "--cmd-file", str(roots / "fx2.sh"),
                     "--timeout", "5m"]) == 1  # fmt: skip
    assert schedule.load_job("p1", "a")["timeout"] == schedule.DEFAULT_TIMEOUT
    # timeout alone works for both kinds; nothing to change is an error
    assert cli.main(["schedule", "edit", "p1", "fx", "--timeout", "5m"]) == 0
    assert schedule.load_job("p1", "fx")["timeout"] == 300
    assert cli.main(["schedule", "edit", "p1", "fx"]) == 1
    assert "--cmd-file" in capsys.readouterr().err


def test_cli_edit_legacy_job_is_an_agent_job(roots, cli_env, capsys):
    make_job(roots, schedule.Spec(every=60))  # no `kind`
    assert (
        cli.main(["schedule", "edit", "p1", "daily", "--cmd-file", str(roots / "prompt.txt")]) == 1
    )
    assert "is an agent job" in capsys.readouterr().err
    assert cli.main(["schedule", "edit", "p1", "daily", "--prompt-file",
                     str(roots / "prompt.txt")]) == 0  # fmt: skip
    assert (schedule.job_dir("p1", "daily") / "prompt.md").read_text() == "do the thing\n"


def test_preflight_command_job_has_no_agent_credential(roots, cmd_env, capsys):
    """Agent job: the missing Claude token is an error (rc 78). Command job: a warning."""
    (roots / "store.json").write_text("{}")
    e, w = cli.sched_preflight("p1", "claude")
    assert e.startswith("CLAUDE_CODE_OAUTH_TOKEN is missing")
    e, w = cli.sched_preflight("p1", None)
    assert e is None
    assert len(w) == 2 and any(x.startswith("CLAUDE_CODE_OAUTH_TOKEN is missing") for x in w)
    assert ANY_MYTOK in w  # other missing secrets stay warnings, as for agent jobs
    # a cmd job needs no agent in [box] agents; an agent job still does
    assert cli.sched_preflight("p2", "claude") == ("claude is not in [box] agents of p2", [])
    assert cli.sched_preflight("p2", None)[0] is None
    # add warns the same way and still succeeds
    assert add_cmd(roots, "--every", "1h") == 0
    err = capsys.readouterr().err
    assert "warning: CLAUDE_CODE_OAUTH_TOKEN is missing" in err and "warning: MYTOK" in err
    assert "login" not in err  # no codex/pi login note for a command job


def test_preflight_command_job_keeps_mount_check(roots, cmd_env):
    code = roots / "code"
    code.mkdir()
    msg, w = cli.sched_preflight("p1", None, None, (str(code),))
    assert msg and "overlaps" in msg and w == []


# ---------------------------------------------------------------- notifications (PLAN §2.7)
HOOK = "https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/hookSECRETVALUE0123456789"


@pytest.fixture
def posts(roots, monkeypatch):
    """Notifications on (shared secret in the env-backend store); notify.post
    records (url, text) instead of using the network. Returns the list."""
    from agentbox import notify

    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    (roots / "cfg").mkdir(exist_ok=True)
    (roots / "cfg" / "config.toml").write_text(
        'secret_backend = "env"\nnotify_webhook_secret = "SLACK_WEBHOOK_URL"\n'
    )
    store = roots / "store.json"
    store.write_text(json.dumps({"AGENTBOX__SHARED_SLACK_WEBHOOK_URL": HOOK}))
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(notify, "post", lambda url, text, timeout: calls.append((url, text)))
    return calls


def transcript_run(roots, text, name="rd", **meta):
    rd = roots / name
    rd.mkdir(exist_ok=True)
    (rd / "transcript.log").write_text(text)
    if meta:
        (rd / "meta.json").write_text(json.dumps(meta))
    return rd


def last_of(job):
    return json.loads((Path(job["dir"]) / "last.json").read_text())


def hist_of(job):
    lines = (Path(job["dir"]) / "history.jsonl").read_text().splitlines()
    return [json.loads(x) for x in lines]


def test_notify_ok_posts_once_with_the_last_transcript_line(roots, posts):
    job = make_job(roots, schedule.Spec(every=60), name="eurusd", profile="fx")
    rd = transcript_run(roots, "fetching\n== check: ECB date 2026-10-05\n\n")
    assert schedule.fire("fx", "eurusd", lambda *a: (0, rd), ok_preflight) == 0
    assert posts == [(HOOK, "agentbox fx/eurusd: ok (exit 0, 0s) — == check: ECB date 2026-10-05")]
    assert last_of(job)["notify"] == "ok" and hist_of(job)[-1]["notify"] == "ok"


def test_notify_nonzero_exit(roots, posts):
    make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "boom: bad thing\n")
    assert schedule.fire("p1", "daily", lambda *a: (3, rd), ok_preflight) == 3
    assert posts == [(HOOK, "agentbox p1/daily: FAILED (exit 3, 0s) — boom: bad thing")]


def test_notify_timeout_skips_the_kill_marker(roots, posts):
    job = make_job(roots, schedule.Spec(every=60), name="household", profile="cves")
    f = Path(job["dir"]) / "job.json"
    f.write_text(json.dumps({**job, "timeout": 3600}))
    rd = transcript_run(
        roots,
        "scanning 40/90\n[agentbox: run killed: timeout after 3600 s]\n",
        killed="timeout after 3600 s",
    )
    assert schedule.fire("cves", "household", lambda *a: (124, rd), ok_preflight) == 124
    assert posts == [
        (HOOK, "agentbox cves/household: TIMEOUT after 1h (exit 124) — scanning 40/90")
    ]


def test_notify_terminated_two_paths(roots, posts, monkeypatch):
    job = make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "working\n[agentbox: run killed: terminated by signal 15]\n")

    def runner(*a):
        raise cli.RunFailed("terminated by signal 15", rd, schedule.RC_TERMINATED)

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 143
    assert posts[-1][1] == "agentbox p1/daily: TERMINATED (exit 143, 0s) — working"
    assert len(posts) == 1

    def during_wait(*a):
        raise schedule.Terminated(15)

    posts.clear()
    monkeypatch.setattr(schedule, "ensure_docker", during_wait)
    assert schedule.fire("p1", "daily", runner, ok_preflight) == 143
    assert [t for _, t in posts] == [
        "agentbox p1/daily: TERMINATED (exit 143, 0s) — terminated by signal 15"
    ]
    assert [h["notify"] for h in hist_of(job)] == ["ok", "ok"]


def test_notify_run_failed_to_start(roots, posts):
    make_job(roots, schedule.Spec(every=60))

    def runner(*a):
        raise cli.RunFailed("box start failed: no space", None)

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 125
    assert posts == [
        (
            HOOK,
            "agentbox p1/daily: RUN FAILED (exit 125, 0s) — run failed: box start failed: no space",
        )
    ]


def test_notify_docker_down(roots, posts, monkeypatch):
    fake_bin(roots / "bin2", "docker", "exit 1\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin2'}:/usr/bin:/bin")
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    make_job(roots, schedule.Spec(every=60), name="household", profile="cves")

    def runner(*a):
        raise AssertionError("must not run")

    rc = schedule.fire("cves", "household", runner, ok_preflight, wait=120, poll=0.1)
    assert rc == schedule.RC_DOCKER_DOWN
    assert posts == [
        (
            HOOK,
            "agentbox cves/household: did not run (exit 69, 0s) — "
            "Docker did not come up within 120 s",
        )
    ]


def test_notify_preflight_failure(roots, posts):
    make_job(roots, schedule.Spec(every=60))
    fix = "CLAUDE_CODE_OAUTH_TOKEN is missing: run `agentbox setup`"
    rc = schedule.fire("p1", "daily", lambda *a: 1 / 0, lambda p, a, m, c: (fix, []))
    assert rc == schedule.RC_PREFLIGHT
    assert posts == [(HOOK, f"agentbox p1/daily: did not run (exit 78, 0s) — {fix}")]


def test_notify_skipped_when_the_job_still_runs(roots, posts):
    import fcntl

    job = make_job(roots, schedule.Spec(every=60))
    with (Path(job["dir"]) / "fire.lock").open("a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert schedule.fire("p1", "daily", lambda *a: 1 / 0, ok_preflight) == schedule.RC_SKIPPED
    assert posts == [
        (HOOK, "agentbox p1/daily: SKIPPED (exit 75) — another run of this job is still active")
    ]
    assert hist_of(job)[-1]["notify"] == "ok"
    assert json.loads((Path(job["dir"]) / "skipped.json").read_text())["notify"] == "ok"
    assert not (Path(job["dir"]) / "last.json").exists()  # a skip never owned last.json


def test_notify_cmd_job_and_legacy_job(roots, posts):
    make_job(roots, schedule.Spec(every=60), kind="cmd")
    rd = transcript_run(roots, "script done\n")
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    assert posts == [(HOOK, "agentbox p1/daily: ok (exit 0, 0s) — script done")]
    # job.json from before command jobs: no `kind`
    posts.clear()
    job = make_job(roots, schedule.Spec(every=60), name="old")
    assert "kind" not in json.loads((Path(job["dir"]) / "job.json").read_text())
    assert schedule.fire("p1", "old", lambda *a: (0, rd), ok_preflight) == 0
    assert posts == [(HOOK, "agentbox p1/old: ok (exit 0, 0s) — script done")]


def test_notify_text_from_the_box_is_neutralised(roots, posts):
    make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "<!channel> <http://evil.example|ok> \x1b[2J& " + "z" * 400 + "\n")
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    text = posts[0][1]
    assert "<" not in text and ">" not in text and "\x1b" not in text
    assert text.startswith("agentbox p1/daily: ok (exit 0, 0s) — &lt;!channel&gt; &lt;http://evil")
    assert text.endswith("…") and len(text.split(" — ", 1)[1]) < 400


def all_text_under(root: Path) -> str:
    out = []
    for f in root.rglob("*"):
        if f.is_file() and f.name != "store.json" and f.name != "config.toml":
            out.append(f.read_bytes().decode("utf-8", "replace"))
    return "\n".join(out)


@pytest.mark.parametrize("how", ["raises", "http500", "no-secret", "backend", "hung"])
@pytest.mark.parametrize("rc", [0, 3])
def test_notify_failure_never_changes_the_fire(roots, posts, monkeypatch, capsys, how, rc):
    from agentbox import notify, secretstore

    job = make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "all good\n")
    if how == "raises":

        def boom(url, text, timeout):
            raise OSError(f"cannot reach {url}")

        monkeypatch.setattr(notify, "post", boom)
    elif how == "http500":

        def boom(url, text, timeout):
            raise notify.NotifyError("HTTP 500")

        monkeypatch.setattr(notify, "post", boom)
    elif how == "no-secret":
        (roots / "store.json").write_text("{}")
    elif how == "backend":

        def locked(cfg, profile):
            raise secretstore.SecretError("keychain read of x failed: locked")

        monkeypatch.setattr(notify, "read_webhook", locked)
    else:
        monkeypatch.setattr(notify, "NOTIFY_TIMEOUT", 0.2)
        monkeypatch.setattr(notify, "post", lambda *a: time.sleep(5))
    assert schedule.fire("p1", "daily", lambda *a: (rc, rd), ok_preflight) == rc
    last = last_of(job)
    assert last["exit_code"] == rc and last["status"] == ("ok" if rc == 0 else "failed")
    assert last["notify"].startswith("error: ") and hist_of(job)[-1]["notify"] == last["notify"]
    err = capsys.readouterr().err
    assert f"schedule p1/daily: notify: {last['notify']}" in err
    for text in (all_text_under(roots), err, json.dumps(last)):
        assert HOOK not in text and "hookSECRET" not in text and "T0AAAAAAA" not in text


def test_notify_success_leaves_no_secret_on_disk_or_in_logs(roots, posts, capsys):
    make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "ok\n")
    assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
    assert posts and "hookSECRET" not in all_text_under(roots) + capsys.readouterr().err


def test_notify_unset_changes_nothing(roots, monkeypatch):
    """Setting absent: no HTTP, no secret read, and the records have no notify field."""
    from agentbox import notify

    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    for name in ("post", "read_webhook"):
        monkeypatch.setattr(notify, name, lambda *a, **k: 1 / 0)
    monkeypatch.setattr("urllib.request.build_opener", lambda *a: 1 / 0)
    job = make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "x\n")
    for _ in range(2):  # no config.toml, then one without the key
        assert schedule.fire("p1", "daily", lambda *a: (0, rd), ok_preflight) == 0
        (roots / "cfg").mkdir(exist_ok=True)
        (roots / "cfg" / "config.toml").write_text('secret_backend = "env"\n')
    assert sorted(last_of(job)) == [
        "agent", "end", "exit_code", "kind", "message", "name", "profile", "run_dir", "start",
        "status", "transcript", "trigger", "warnings",
    ]  # fmt: skip
    assert all("notify" not in h for h in hist_of(job))


def test_ls_shows_a_failed_notification_as_a_warning(roots, cli_env, posts, monkeypatch, capsys):
    from agentbox import notify

    monkeypatch.setattr(
        notify, "post", lambda *a: (_ for _ in ()).throw(notify.NotifyError("HTTP 404"))
    )
    (roots / "cfg" / "config.toml").write_text(
        'secret_backend = "env"\nsecret_prefix = "agentbox"\n'
        'notify_webhook_secret = "SLACK_WEBHOOK_URL"\n'
    )
    make_job(roots, schedule.Spec(every=60))
    assert schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight) == 0
    capsys.readouterr()
    assert cli.main(["schedule", "ls", "p1"]) == 0
    out = capsys.readouterr().out
    assert "  warning: notification failed: HTTP 404" in out
    # a good notification shows nothing
    monkeypatch.setattr(notify, "post", lambda *a: None)
    assert schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight) == 0
    capsys.readouterr()
    assert cli.main(["schedule", "ls", "p1"]) == 0
    assert "notification" not in capsys.readouterr().out


def test_notify_script_exit_codes_are_not_agentbox_outcomes(roots, posts):
    """A command script that exits 124, 125 or 143 itself is FAILED: the CLI did not
    kill it (no meta `killed`), and the runner did not raise."""
    make_job(roots, schedule.Spec(every=60), kind="cmd")
    rd = transcript_run(roots, "the script quit\n", killed=None)
    for rc in (124, 125, 143):
        posts.clear()
        assert schedule.fire("p1", "daily", lambda *a, rc=rc: (rc, rd), ok_preflight) == rc
        assert posts == [(HOOK, f"agentbox p1/daily: FAILED (exit {rc}, 0s) — the script quit")]


def test_notify_runner_exception_is_run_failed_and_signal_is_terminated(roots, posts):
    make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "log\n")

    def start_fail(*a):
        raise cli.RunFailed("boom", rd)  # rc None -> 125

    assert schedule.fire("p1", "daily", start_fail, ok_preflight) == 125
    assert posts[-1][1].startswith("agentbox p1/daily: RUN FAILED (exit 125, 0s)")

    def sigterm(*a):
        raise cli.RunFailed("terminated by signal 15", rd, schedule.RC_TERMINATED)

    assert schedule.fire("p1", "daily", sigterm, ok_preflight) == 143
    assert posts[-1][1].startswith("agentbox p1/daily: TERMINATED (exit 143, 0s)")


def test_notify_fallback_text_survives_a_stopped_note(roots, posts):
    """Regression: `stopped` from meta.json must not replace the real error text."""
    job = make_job(roots, schedule.Spec(every=60))
    rd = transcript_run(roots, "", stopped="killed leftover processes (sleep 99)")

    def runner(*a):
        raise cli.RunFailed("box start failed: no space", rd)

    assert schedule.fire("p1", "daily", runner, ok_preflight) == 125
    assert posts == [
        (
            HOOK,
            "agentbox p1/daily: RUN FAILED (exit 125, 0s) — run failed: box start failed: no space",
        )
    ]
    assert last_of(job)["stopped"] == "stopped: killed leftover processes (sleep 99)"
    # terminated arm, empty transcript
    posts.clear()

    rd2 = transcript_run(roots, "", name="rd2", stopped="killed leftover processes (x)")
    e = schedule.Terminated(15)
    e.run_dir = rd2

    def runner2(*a):
        raise e

    assert schedule.fire("p1", "daily", runner2, ok_preflight) == 143
    assert posts[-1][1].endswith("— terminated by signal 15")


def test_final_outcome_is_on_disk_before_the_post(roots, posts, monkeypatch):
    """A kill during the post must leave the true status, not `running`."""
    from agentbox import notify

    job = make_job(roots, schedule.Spec(every=60))
    jd = Path(job["dir"])
    rd = transcript_run(roots, "done\n")
    seen = {}

    def post(url, text, timeout):
        seen["last"] = last_of(job)
        seen["hist"] = (jd / "history.jsonl").exists()

    monkeypatch.setattr(notify, "post", post)
    assert schedule.fire("p1", "daily", lambda *a: (3, rd), ok_preflight) == 3
    during = seen["last"]
    assert during["status"] == "failed" and during["exit_code"] == 3
    assert during["end"] and during["run_dir"] == str(rd) and during["transcript"]
    assert during["warnings"] == [] and "pid" not in during and "notify" not in during
    assert seen["hist"] is False  # the history line is appended once, after the post
    final = last_of(job)
    assert final == {**during, "notify": "ok"}
    assert hist_of(job) == [final]


def test_skip_outcome_is_on_disk_before_the_post(roots, posts, monkeypatch):
    import fcntl

    from agentbox import notify

    job = make_job(roots, schedule.Spec(every=60))
    jd = Path(job["dir"])
    seen = {}

    def post(url, text, timeout):
        seen["skipped"] = json.loads((jd / "skipped.json").read_text())
        seen["hist"] = (jd / "history.jsonl").exists()

    monkeypatch.setattr(notify, "post", post)
    with (jd / "fire.lock").open("a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
        assert schedule.fire("p1", "daily", lambda *a: 1 / 0, ok_preflight) == schedule.RC_SKIPPED
    assert seen["skipped"]["status"] == "skipped" and "notify" not in seen["skipped"]
    assert seen["hist"] is False
    assert json.loads((jd / "skipped.json").read_text())["notify"] == "ok"
    assert [h["notify"] for h in hist_of(job)] == ["ok"]


def test_unset_writes_each_file_once(roots, monkeypatch):
    """Setting absent: one last.json write, one history line, as before."""
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    writes = []
    real = schedule.write_private

    def spy(f, data, mode=0o600):
        writes.append(Path(f).name)
        real(f, data, mode)

    monkeypatch.setattr(schedule, "write_private", spy)
    assert schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight) == 0
    assert writes == ["last.json", "last.json"]  # "running" marker, then the final record
    assert len(hist_of(job)) == 1


# ---------------------------------------------------------------- trigger (PLAN §2.7, f1)
def fire_once(roots, monkeypatch, runner=None, spec=None):
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, spec or schedule.Spec(every=60))
    rc = schedule.fire("p1", "daily", runner or (lambda *a: (0, roots)), ok_preflight)
    return job, rc


def test_fire_records_trigger_schedule_by_default(roots, monkeypatch):
    monkeypatch.delenv(schedule.TRIGGER_ENV, raising=False)
    job, rc = fire_once(roots, monkeypatch)
    assert rc == 0 and last_of(job)["trigger"] == "schedule"
    assert hist_of(job)[-1]["trigger"] == "schedule"


def test_fire_records_run_now_trigger(roots, monkeypatch):
    monkeypatch.setenv(schedule.TRIGGER_ENV, "run-now")
    job, rc = fire_once(roots, monkeypatch)
    assert rc == 0 and last_of(job)["trigger"] == "run-now"
    assert hist_of(job)[-1]["trigger"] == "run-now"


@pytest.mark.parametrize("value", ["manual", "", "Schedule", "run-now ", "x" * 200])
def test_fire_refuses_an_unknown_trigger_with_exit_78(roots, monkeypatch, value):
    monkeypatch.setenv(schedule.TRIGGER_ENV, value)
    ran = []
    job, rc = fire_once(roots, monkeypatch, runner=lambda *a: ran.append(1) or (0, roots))
    assert rc == schedule.RC_PREFLIGHT == 78 and ran == []
    last = last_of(job)
    assert last["status"] == "failed" and last["exit_code"] == 78
    assert (
        schedule.TRIGGER_ENV in last["message"]
        and "is not one of schedule, run-now" in last["message"]
    )
    assert len(last["message"]) < 200  # a long value is cut
    assert last["trigger"] == "schedule" and hist_of(job)[-1]["message"] == last["message"]


def test_skipped_fire_records_the_trigger(roots, monkeypatch):
    monkeypatch.setenv(schedule.TRIGGER_ENV, "run-now")
    fake_bin(roots / "bin", "docker", "exit 0\n")
    monkeypatch.setenv("PATH", f"{roots / 'bin'}:/usr/bin:/bin")
    job = make_job(roots, schedule.Spec(every=60))
    import fcntl

    with (Path(job["dir"]) / "fire.lock").open("a") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        assert schedule.fire("p1", "daily", lambda *a: (0, roots), ok_preflight) == 75
    assert hist_of(job)[-1]["status"] == "skipped" and hist_of(job)[-1]["trigger"] == "run-now"


def test_trigger_variable_is_not_passed_to_scheduled_jobs(roots, monkeypatch):
    assert schedule.TRIGGER_ENV not in schedule.PASS_ENV
    monkeypatch.setenv(schedule.TRIGGER_ENV, "run-now")
    assert schedule.TRIGGER_ENV not in schedule.job_env()
    make_job(roots, schedule.Spec(every=60))
    assert schedule.TRIGGER_ENV not in json.loads(
        (schedule.job_dir("p1", "daily") / "job.json").read_text())["env"]  # fmt: skip


def test_run_now_sets_the_trigger_in_the_fire_environment(roots, cli_env, monkeypatch, capsys):
    seen = {}

    def fake_run(argv, env=None, **kw):
        seen["argv"], seen["env"] = argv, env
        return _cp(0)

    monkeypatch.setattr(schedule, "launchctl", lambda *a: _cp(1 if a[0] == "print" else 0))
    pf = str(roots / "prompt.txt")
    assert cli.main(["schedule", "add", "p1", "--name", "m", "--agent", "claude",
                     "--prompt-file", pf, "--every", "1h"]) == 0  # fmt: skip
    monkeypatch.setattr(cli.subprocess, "run", fake_run)
    monkeypatch.setenv(schedule.TRIGGER_ENV, "schedule")  # the caller's value does not matter
    assert cli.main(["schedule", "run-now", "p1", "m"]) == 0
    job = json.loads((schedule.job_dir("p1", "m") / "job.json").read_text())
    assert seen["env"] == {**job["env"], schedule.TRIGGER_ENV: "run-now"}
    assert schedule.TRIGGER_ENV not in job["env"]  # job.json never holds it
    assert seen["argv"] == job["argv"]


# ---------------------------------------------------------------- source and drift (PLAN §2.7, f1)
def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_add_stores_source_and_hash_for_prompt_and_command_jobs(roots, cmd_env):
    assert cli.main(["schedule", "add", "p1", "--name", "a", "--agent", "claude",
                     "--prompt-file", str(roots / "prompt.txt"), "--every", "1h"]) == 0  # fmt: skip
    job = json.loads((schedule.job_dir("p1", "a") / "job.json").read_text())
    assert job["source"] == str((roots / "prompt.txt").resolve())
    assert job["source_sha256"] == sha(b"do the thing\n")
    assert add_cmd(roots, "--every", "1h", profile="p1") == 0
    job = json.loads((schedule.job_dir("p1", "fx") / "job.json").read_text())
    assert job["source"] == str((roots / "fx.sh").resolve())
    assert job["source_sha256"] == sha((roots / "fx.sh").read_bytes())


def test_add_resolves_a_relative_source_path(roots, cmd_env, monkeypatch):
    monkeypatch.chdir(roots)
    assert cli.main(["schedule", "add", "p1", "--name", "r", "--cmd-file", "fx.sh",
                     "--every", "1h"]) == 0  # fmt: skip
    job = json.loads((schedule.job_dir("p1", "r") / "job.json").read_text())
    assert job["source"] == str((roots / "fx.sh").resolve()) and os.path.isabs(job["source"])


def test_edit_updates_source_and_hash_but_timeout_alone_does_not(roots, cmd_env):
    assert add_cmd(roots, "--every", "1h") == 0
    jf = schedule.job_dir("p1", "fx") / "job.json"
    before = json.loads(jf.read_text())
    new = roots / "fx2.sh"
    new.write_text("echo v2\n")
    assert cli.main(["schedule", "edit", "p1", "fx", "--timeout", "5m"]) == 0
    after = json.loads(jf.read_text())
    assert after["source"] == before["source"] and after["timeout"] == 300
    assert cli.main(["schedule", "edit", "p1", "fx", "--cmd-file", str(new)]) == 0
    after = json.loads(jf.read_text())
    assert after["source"] == str(new.resolve()) and after["source_sha256"] == sha(b"echo v2\n")
    assert after["created"] == before["created"] and after["timeout"] == 300  # nothing else moves
    assert (jf.parent / "command.sh").read_text() == "echo v2\n"


def test_edit_of_an_old_job_without_source_adds_it(roots, cmd_env):
    make_job(roots, schedule.Spec(every=60), kind="cmd")
    assert "source" not in json.loads((schedule.job_dir("p1", "daily") / "job.json").read_text())
    new = roots / "n.sh"
    new.write_text("true\n")
    assert cli.main(["schedule", "edit", "p1", "daily", "--cmd-file", str(new)]) == 0
    job = json.loads((schedule.job_dir("p1", "daily") / "job.json").read_text())
    assert job["source"] == str(new.resolve()) and job["source_sha256"] == sha(b"true\n")


def drift_job(roots, source, content="v1\n", **kw):
    job = make_job(roots, schedule.Spec(every=60), kind="cmd", **kw)
    (Path(job["dir"]) / "command.sh").write_text(content)
    job["source"] = str(source)
    return job


def test_source_drift_states(roots):
    src = roots / "brief.sh"
    src.write_text("v1\n")
    job = drift_job(roots, src)
    assert schedule.source_drift(job) is None  # same bytes
    src.write_text("v2\n")
    kind, text = schedule.source_drift(job)
    assert kind == "differs" and text.startswith(f"job copy differs from {src} (since ")
    src.unlink()
    assert schedule.source_drift(job) == ("gone", "source gone")
    assert schedule.source_drift({**job, "source": str(roots / "nodir" / "x")})[0] == "gone"
    job.pop("source")
    assert schedule.source_drift(job) is None  # a job from before f1


def test_source_drift_refuses_anything_but_a_plain_file(roots):
    plain = roots / "real.sh"
    plain.write_text("v1\n")
    link = roots / "link.sh"
    link.symlink_to(plain)
    job = drift_job(roots, link)
    assert schedule.source_drift(job) == ("not_plain", "source is not a plain file")  # symlink
    fifo = roots / "fifo.sh"
    os.mkfifo(fifo)
    t0 = time.monotonic()
    job = drift_job(roots, fifo)
    assert schedule.source_drift(job) == ("not_plain", "source is not a plain file")
    assert time.monotonic() - t0 < 5  # the open does not block on a FIFO
    job = drift_job(roots, roots)  # a directory
    assert schedule.source_drift(job)[0] == "not_plain"
    big = roots / "big.sh"
    big.write_bytes(b"x" * (schedule.SOURCE_MAX + 1))
    assert schedule.source_drift(drift_job(roots, big)) == (
        "not_plain",
        "source is not a plain file",
    )
    ok = roots / "edge.sh"
    ok.write_bytes(b"y" * schedule.SOURCE_MAX)  # exactly 1 MiB is still read
    assert schedule.source_drift(drift_job(roots, ok, content="other"))[0] == "differs"


def test_source_drift_is_read_only_and_leaks_no_content(roots):
    src = roots / "s.sh"
    src.write_text("SECRET_BODY\n")
    job = drift_job(roots, src, content="other\n")
    before = src.stat().st_mtime_ns
    kind, text = schedule.source_drift(job)
    assert "SECRET_BODY" not in text and src.stat().st_mtime_ns == before
    assert src.read_text() == "SECRET_BODY\n"


def test_ls_warns_about_drift(roots, cmd_env, capsys):
    src = roots / "fx.sh"
    assert add_cmd(roots, "--every", "1h") == 0
    capsys.readouterr()
    assert cli.main(["schedule", "ls"]) == 0
    assert "warning: job copy" not in capsys.readouterr().out  # same bytes
    src.write_text("echo changed\n")
    assert cli.main(["schedule", "ls"]) == 0
    out = capsys.readouterr().out
    fix = f"agentbox schedule edit p1 fx --cmd-file {src.resolve()}"
    assert f"warning: job copy differs from {src.resolve()}; run `{fix}` to update it" in out
    assert "echo changed" not in out
    src.unlink()
    assert cli.main(["schedule", "ls"]) == 0
    assert f"warning: source gone ({src.resolve()})" in capsys.readouterr().out
    os.mkfifo(src)
    assert cli.main(["schedule", "ls"]) == 0
    assert "warning: source is not a plain file" in capsys.readouterr().out


def test_ls_drift_for_an_agent_job_names_prompt_file(roots, cli_env, capsys, monkeypatch):
    monkeypatch.setattr(schedule, "launchctl", lambda *a: _cp(1 if a[0] == "print" else 0))
    assert cli.main(["schedule", "add", "p1", "--name", "a", "--agent", "claude",
                     "--prompt-file", str(roots / "prompt.txt"), "--every", "1h"]) == 0  # fmt: skip
    (roots / "prompt.txt").write_text("changed\n")
    capsys.readouterr()
    assert cli.main(["schedule", "ls"]) == 0
    assert "agentbox schedule edit p1 a --prompt-file" in capsys.readouterr().out


def test_ls_has_no_drift_line_for_a_job_without_source(roots, cmd_env, capsys):
    make_job(roots, schedule.Spec(every=60), kind="cmd")
    assert cli.main(["schedule", "ls"]) == 0
    assert "warning" not in capsys.readouterr().out


# ---------------------------------------------------------------- report job helpers (PLAN §2.8)
def test_report_label_and_tag_are_their_own(roots, monkeypatch):
    assert schedule.report_label() == "com.agentbox-unit._report"
    assert schedule.report_tag() == "# agentbox:_report"
    assert schedule.label_for("p1", "daily") == "com.agentbox-unit.p1.daily"
    monkeypatch.setenv("AGENTBOX_LAUNCHD_PREFIX", "bad prefix")
    with pytest.raises(ScheduleError, match="not a valid label prefix"):
        schedule.report_label()


def test_crontab_tag_helpers_keep_other_entries():
    base = "0 1 * * * echo mine\n"
    t1 = schedule.crontab_set(base, "p1", "daily", "0 7 * * * job")
    t2 = schedule.crontab_set_tag(t1, schedule.report_tag(), "30 9 * * * report")
    assert t2 == (base + "# agentbox:p1:daily\n0 7 * * * job\n"
                  "# agentbox:_report\n30 9 * * * report\n")  # fmt: skip
    t3 = schedule.crontab_set_tag(t2, schedule.report_tag(), "45 9 * * * report")
    assert t3.count("# agentbox:_report") == 1 and "45 9" in t3 and "30 9 * * * report" not in t3
    assert schedule.crontab_remove_tag(t3, schedule.report_tag()) == t1
    assert schedule.crontab_remove(t1, "p1", "daily") == base


def test_fires_between_does_not_change_next_fires():
    spec = schedule.Spec(cron="0 7 * * 1-5")
    now = datetime(2026, 9, 23, 7, 0, 30)
    assert schedule.next_fires(spec, now) == [datetime(2026, 9, 24, 7, 0),
                                             datetime(2026, 9, 25, 7, 0),
                                             datetime(2026, 9, 28, 7, 0)]  # fmt: skip


def test_linux_installed_matches_the_whole_tag_line(roots, monkeypatch):
    monkeypatch.setattr(schedule, "is_macos", lambda: False)
    job = make_job(roots, schedule.Spec(every=3600), profile="p", name="a")
    text = "0 1 * * * echo mine\n# agentbox:p:ab\n0 * * * * other\n"
    monkeypatch.setattr(schedule, "crontab_read", lambda: text)
    assert schedule.installed(job) == "no crontab"  # `p:a` is only a prefix of `p:ab`
    text += "# agentbox:p:a\n0 * * * * mine\n"
    assert schedule.installed(job) == "in crontab"
    text = "# agentbox:p:ab\n0 * * * * x\n  # agentbox:p:a  \n0 * * * * y\n"
    assert schedule.installed(job) == "in crontab"  # same as crontab_remove: strip, then equal
