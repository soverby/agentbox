"""CLI flows without Docker: init, allow (reload + restore), argv split."""

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
    monkeypatch.setattr("agentbox.profile.check_mount_host", lambda h, d=False: h)
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


def run_box(roots, monkeypatch, up_fails=False, others=()):
    setup_running_box(roots, monkeypatch, {})
    events = []
    monkeypatch.setattr(boxmod, "is_running", lambda b: False)

    def ensure_up(b, accept=False):
        events.append("up")
        if up_fails:
            raise cli.CliError("fast isolation checks failed")

    seen = {}

    def run(cmd, stdout, stderr, stdin):
        seen["cmd"] = cmd
        seen["stdin"] = stdin.read()
        stdout.write("Not logged in\n")
        return subprocess.CompletedProcess(cmd, 1)

    monkeypatch.setattr(cli, "ensure_up", ensure_up)
    monkeypatch.setattr(cli.subprocess, "run", run)
    monkeypatch.setattr(boxmod, "other_processes", lambda b: list(others))
    monkeypatch.setattr(boxmod, "down", lambda b, volumes=False: events.append("down"))
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


def test_run_leaves_box_up_when_joined(roots, monkeypatch):
    events, _ = run_box(roots, monkeypatch, others=["/usr/local/bin/with-secrets sleep 40"])
    pf = roots / "p.txt"
    pf.write_text("hi")
    cli.main(["run", "demo", "--agent", "claude", "--prompt-file", str(pf)])
    assert events == ["up"]  # no down


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
    monkeypatch.setattr(boxmod, "up", lambda b, accept=False: None)
    monkeypatch.setattr(doc, "fast", lambda b: [doc.Result("FAIL", "1", "default route present")])
    b = boxmod.load("demo")
    with pytest.raises(cli.CliError) as e:
        cli.ensure_up(b)
    msg = str(e.value)
    assert "FAIL 1: default route present" in msg and "agentbox up demo" in msg
