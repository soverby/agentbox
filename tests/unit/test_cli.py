"""CLI flows without Docker: init, allow (reload + restore), argv split."""

import os
import subprocess
import tomllib

import pytest
from agentbox import box as boxmod
from agentbox import cli, paths
from agentbox.profile import parse_profile


@pytest.fixture
def roots(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "cfg"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "state"))
    return tmp_path


def test_init_refuses_overwrite(roots, monkeypatch):
    # A path accepted by host checks (stub the check to accept anything).
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    assert cli.main(["init", "p2", "--mount", str(roots), "--agents", "claude,pi", "--open"]) == 0
    f = paths.profile_file("p2")
    doc = tomllib.loads(f.read_text())
    assert doc["box"]["agents"] == ["claude", "pi"] and doc["network"]["mode"] == "open"
    assert f.stat().st_mode & 0o777 == 0o600
    assert cli.main(["init", "p2", "--mount", str(roots)]) == 1  # refuses overwrite
    assert cli.main(["init", "Bad_Name", "--mount", str(roots)]) == 1


def test_init_denied_mount_returns_error(roots, capsys):
    rc = cli.main(["init", "p1", "--mount", "/etc"])
    assert rc == 1 and "profile not written" in capsys.readouterr().err
    assert not paths.profile_file("p1").exists()


def test_dash_dash_only_for_sessions(capsys):
    assert cli.main(["ls", "--", "x"]) == 2


def setup_running_box(roots, monkeypatch, dc_results):
    text = '[[mount]]\nhost = "/w/p"\n\n[network]\n# my comment\nallow = []\n'
    paths.profiles_dir().mkdir(parents=True)
    paths.profile_file("demo").write_text(text)
    state = paths.state_dir("demo")
    (state / "subnet").write_text("5\n")

    def load(name):
        p = parse_profile(tomllib.loads(paths.profile_file(name).read_text()), name)
        return boxmod.Box(name, p, state, paths.Config())

    calls = []

    def dc(b, *args, **kw):
        calls.append(args)
        rc, out = dc_results.get(args[3] if len(args) > 3 else "", (0, ""))
        return subprocess.CompletedProcess(args, rc, out, "")

    monkeypatch.setattr(boxmod, "load", load)
    monkeypatch.setattr(boxmod, "is_running", lambda b: True)
    monkeypatch.setattr(boxmod, "dc", dc)
    # initial allowlist as rendered at up
    b = load("demo")
    ctx = boxmod.ctx_for(b, 5)
    from agentbox import egress

    egress.write(ctx.conf_dir, boxmod.render_egress(b, ctx))
    return text, state, calls


def test_allow_reload(roots, monkeypatch):
    text, state, calls = setup_running_box(roots, monkeypatch, {})
    assert cli.main(["allow", "demo", "www.wikipedia.org"]) == 0
    new = paths.profile_file("demo").read_text()
    assert "# my comment" in new and 'allow = ["www.wikipedia.org"]' in new
    assert "www.wikipedia.org\n" in (state / "egress" / "agent.allow").read_text()
    verbs = [c[3] for c in calls]
    assert verbs == ["squid", "squid"] and calls[0][4:6] == ("-k", "parse")
    assert calls[1][4:6] == ("-k", "reconfigure")


def test_allow_parse_failure_restores(roots, monkeypatch):
    # Injected failure: `squid -k parse` reports FATAL.
    text, state, calls = setup_running_box(roots, monkeypatch, {"squid": (1, "FATAL: bad config")})
    before = (state / "egress" / "agent.allow").read_text()
    assert cli.main(["allow", "demo", "new.example.net"]) == 1
    assert paths.profile_file("demo").read_text() == text
    assert (state / "egress" / "agent.allow").read_text() == before
    assert len(calls) == 1  # never reconfigured


def test_allow_invalid(roots, monkeypatch):
    text, state, calls = setup_running_box(roots, monkeypatch, {})
    assert cli.main(["allow", "demo", "10.0.0.1"]) == 1
    assert paths.profile_file("demo").read_text() == text and calls == []


def run_box(roots, monkeypatch, up_fails=False, others=(), running=False, wait=None):
    setup_running_box(roots, monkeypatch, {})
    events = []
    monkeypatch.setattr(boxmod, "is_running", lambda b: running)

    def ensure_up(b, accept=False):
        events.append("up")
        if up_fails:
            raise cli.CliError("fast isolation checks failed")

    seen = {}

    class Popen:  # the `docker compose exec` of a headless run
        def __init__(self, cmd, stdout, stderr, stdin):
            seen["cmd"] = cmd
            seen["stdin"] = stdin.read()
            r, w = os.pipe()
            os.write(w, b"Not logged in\n")
            os.close(w)
            self.stdout = os.fdopen(r, "rb")

        def wait(self, timeout=None):
            if wait is not None and not seen.get("waited"):
                seen["waited"] = timeout
                wait(timeout)
            return 1

        def kill(self):
            events.append("kill")

    monkeypatch.setattr(cli, "ensure_up", ensure_up)
    monkeypatch.setattr(cli.subprocess, "Popen", Popen)
    monkeypatch.setattr(boxmod, "other_processes", lambda b: list(others))
    monkeypatch.setattr(boxmod, "down", lambda b, volumes=False: events.append("down"))
    monkeypatch.setattr(boxmod, "down_locked", lambda b, volumes=False: events.append("down"))
    return events, seen


def test_run_prompt_on_stdin(roots, monkeypatch):
    events, seen = run_box(roots, monkeypatch)
    pf = roots / "prompt.txt"
    big = b"--- starts with dashes\n" + b"x" * 200_000
    pf.write_bytes(big)
    assert cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)]) == 1
    assert seen["stdin"] == big
    assert seen["cmd"][-2:] == ["--dangerously-skip-permissions", "-p"]
    assert all(len(a) < 1000 for a in seen["cmd"])  # prompt never in argv
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    assert (rd / "exit_code").read_text() == "1\n"
    assert events == ["up", "down"]


def test_run_exit_code_when_box_fails(roots, monkeypatch):
    events, seen = run_box(roots, monkeypatch, up_fails=True)
    pf = roots / "p.txt"
    pf.write_text("hi")
    assert cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)]) == 1
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    assert (rd / "exit_code").read_text() == "125\n"
    assert "box start failed" in (rd / "transcript.log").read_text()
    assert "cmd" not in seen


def test_run_stops_unpinned_box_with_leftovers(roots, monkeypatch):
    """P8: other processes without a session are agent leftovers: box stops."""
    events, _ = run_box(roots, monkeypatch, others=["sh -c while :; do sleep 1; done"])
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up", "down"]
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    meta = __import__("json").loads((rd / "meta.json").read_text())
    assert "left_up" not in meta
    assert meta["stopped"] == "killed leftover processes (sh -c while :; do sleep 1; done)"


def test_run_leaves_pinned_box_up_with_leftovers(roots, monkeypatch):
    events, _ = run_box(roots, monkeypatch, others=["sleep 99"])
    pf = roots / "p.txt"
    pf.write_text("hi")
    orig = cli.ensure_up

    def up_and_pin(b):  # the user pinned the box (`up`) while the run started
        orig(b)
        boxmod.pin(b)

    monkeypatch.setattr(cli, "ensure_up", up_and_pin)
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up"]
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    meta = __import__("json").loads((rd / "meta.json").read_text())
    assert "stopped" not in meta and "left_up" not in meta


def test_run_leaves_box_up_when_session_lock_held(roots, monkeypatch):
    events, _ = run_box(roots, monkeypatch)
    import fcntl

    held = (paths.state_dir("demo") / "session.lock").open("a")
    fcntl.flock(held, fcntl.LOCK_SH)  # another CLI session
    pf = roots / "p.txt"
    pf.write_text("hi")
    try:
        cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    finally:
        held.close()
    assert events == ["up"]


def test_fast_failure_message(roots, monkeypatch):
    from agentbox import doctor as doc

    setup_running_box(roots, monkeypatch, {})
    monkeypatch.setattr(boxmod, "up", lambda b, accept=False, explicit=False: None)
    monkeypatch.setattr(doc, "fast", lambda b: [doc.Result("FAIL", "1", "default route present")])
    b = boxmod.load("demo")
    with pytest.raises(cli.CliError) as e:
        cli.ensure_up(b)
    msg = str(e.value)
    assert "FAIL 1: default route present" in msg and "agentbox up demo" in msg


def test_run_stops_running_unpinned_box(roots, monkeypatch):
    """Reviewer repro: overlapping runs; the one that found the box running
    must stop it too (else the box stays up after both)."""
    events, _ = run_box(roots, monkeypatch, running=True)
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up", "down"]


def test_run_keeps_pinned_box(roots, monkeypatch, capsys):
    events, _ = run_box(roots, monkeypatch, running=True)
    b = boxmod.load("demo")
    boxmod.pin(b)
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up"] and boxmod.is_pinned(b)
    assert "leaving it up" not in capsys.readouterr().err


def test_stale_pin_cleared_when_box_not_running(roots, monkeypatch):
    events, _ = run_box(roots, monkeypatch, running=False)
    boxmod.pin(boxmod.load("demo"))
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up", "down"]


def test_down_clears_pin(roots, monkeypatch):
    setup_running_box(roots, monkeypatch, {})
    b = boxmod.load("demo")
    boxmod.pin(b)
    monkeypatch.setattr(boxmod, "dc", lambda *a, **k: subprocess.CompletedProcess(a, 0, "", ""))
    boxmod.down(b)
    assert not boxmod.is_pinned(b)


def test_up_pins(roots, monkeypatch):
    setup_running_box(roots, monkeypatch, {})
    monkeypatch.setattr(cli, "ensure_up", lambda b, *a, **k: None)
    assert cli.main(["up", "demo"]) == 0
    assert boxmod.is_pinned(boxmod.load("demo"))


def test_run_timeout_kills(roots, monkeypatch):
    def expire(timeout):
        raise subprocess.TimeoutExpired("x", timeout)

    events, seen = run_box(roots, monkeypatch, wait=expire)
    killed = []
    monkeypatch.setattr(
        cli, "kill_run", lambda b, rid, p, all_procs=False: killed.append((rid, all_procs))
    )
    pf = roots / "p.txt"
    pf.write_text("hi")
    rc = cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf), "--timeout", "1m"])
    assert rc == 124 and seen["waited"] == 60
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    assert killed == [(rd.name, True)] and (rd / "exit_code").read_text() == "124\n"
    assert "run killed: timeout after 60 s" in (rd / "transcript.log").read_text()
    assert f"AGENTBOX_RUN={rd.name}" in seen["cmd"]
    assert events == ["up", "down"]


def test_run_terminated_cleans_up(roots, monkeypatch):
    def term(timeout):
        raise cli.Terminated(15)

    events, _ = run_box(roots, monkeypatch, wait=term)
    killed = []
    monkeypatch.setattr(cli, "kill_run", lambda b, rid, p, all_procs=False: killed.append(rid))
    pf = roots / "p.txt"
    pf.write_text("hi")
    b = boxmod.load("demo")
    with pytest.raises(cli.Terminated):
        cli.run_headless(b, "claude", pf, None, "/")
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    assert killed == [rd.name] and (rd / "exit_code").read_text() == "143\n"
    assert events == ["up", "down"]


def test_run_prunes_old_runs(roots, monkeypatch):
    events, _ = run_box(roots, monkeypatch)
    import dataclasses

    real_load = boxmod.load
    monkeypatch.setattr(boxmod, "load", lambda n: dataclasses.replace(
        real_load(n), cfg=paths.Config(runs_keep=3)))  # fmt: skip
    runs = paths.state_dir("demo") / "runs"
    for i in range(5):
        (runs / f"20200101T00000{i}Z-claude").mkdir(parents=True)
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    names = sorted(p.name for p in runs.iterdir())
    assert len(names) == 3 and names[0] == "20200101T000003Z-claude"


@pytest.mark.parametrize(
    "running,pinned,expect",
    [(False, False, ["up", "full", "down"]), (True, False, ["full"]), (True, True, ["full"])],
)
def test_doctor_stops_box_it_started(roots, monkeypatch, running, pinned, expect):
    """P8: doctor on a stopped box stops it again; a running box stays as it is."""
    from agentbox import doctor as doc

    setup_running_box(roots, monkeypatch, {})
    events = []
    monkeypatch.setattr(boxmod, "is_running", lambda b: running)
    monkeypatch.setattr(boxmod, "up", lambda b, accept=False, explicit=False: events.append("up"))
    monkeypatch.setattr(doc, "full", lambda b: events.append("full") or [])
    monkeypatch.setattr(boxmod, "other_processes", lambda b: [])
    monkeypatch.setattr(boxmod, "down_locked", lambda b, volumes=False: events.append("down"))
    if pinned:
        boxmod.pin(boxmod.load("demo"))
    assert cli.main(["doctor", "demo"]) == 0
    assert events == expect


def test_doctor_keeps_box_pinned_meanwhile(roots, monkeypatch):
    from agentbox import doctor as doc

    setup_running_box(roots, monkeypatch, {})
    events = []
    monkeypatch.setattr(boxmod, "is_running", lambda b: False)
    monkeypatch.setattr(boxmod, "up", lambda b, accept=False, explicit=False: events.append("up"))
    monkeypatch.setattr(doc, "full", lambda b: boxmod.pin(b) or [])  # user `up` meanwhile
    monkeypatch.setattr(boxmod, "down_locked", lambda b, volumes=False: events.append("down"))
    assert cli.main(["doctor", "demo"]) == 0
    assert events == ["up"]


@pytest.mark.parametrize("argv,want", [(["down", "p3"], False), (["down", "-v", "p3"], True),
                                       (["down", "--volumes", "p3"], True)])  # fmt: skip
def test_down_volumes_flag(roots, monkeypatch, argv, want):
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False, **kw: h)
    assert cli.main(["init", "p3", "--mount", str(roots)]) == 0
    seen = []
    monkeypatch.setattr(boxmod, "down", lambda b, volumes=False: seen.append(volumes))
    assert cli.main(argv) == 0
    assert seen == [want]


def test_run_records_host_config_changes(roots, monkeypatch, capsys):
    from agentbox import hostscan

    events, _ = run_box(roots, monkeypatch)
    snaps = iter([
        {"items": {"/w/p: .envrc": "missing"}, "incomplete": False},
        {"items": {"/w/p: .envrc": "sha256:abc"}, "incomplete": False},
    ])  # fmt: skip
    monkeypatch.setattr(hostscan, "snapshot", lambda p, budget=1.0: next(snaps))
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    rd = sorted((paths.state_dir("demo") / "runs").iterdir())[-1]
    meta = __import__("json").loads((rd / "meta.json").read_text())
    assert meta["host_config_changes"] == ["/w/p: .envrc: added: sha256:abc"]
    assert not (rd / "hostscan.json").exists()
    err = capsys.readouterr().err
    assert "WARNING: host-executed config changed" in err and "/w/p: .envrc" in err


def test_session_prints_host_config_changes(roots, monkeypatch, capsys):
    from agentbox import hostscan

    setup_running_box(roots, monkeypatch, {})
    monkeypatch.setattr(cli, "ensure_up", lambda b: None)
    monkeypatch.setattr(cli.subprocess, "call", lambda argv: 0)
    snaps = iter([
        {"items": {"/w/p: .git/config [core.fsmonitor]": "missing"}, "incomplete": False},
        {"items": {"/w/p: .git/config [core.fsmonitor]": "ab12 x"}, "incomplete": True},
    ])  # fmt: skip
    monkeypatch.setattr(hostscan, "snapshot", lambda p, budget=1.0: next(snaps))
    assert cli.main(["shell", "demo"]) == 0
    err = capsys.readouterr().err
    assert "[core.fsmonitor]: added: ab12 x" in err and "scan incomplete" in err
    assert not list((paths.state_dir("demo") / "hostscan").iterdir())
