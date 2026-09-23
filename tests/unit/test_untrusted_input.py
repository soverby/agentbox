"""Agent-controlled input to the CLI (P6 review round 1): terminal escapes,
unbounded / blocking in-box reads, config merges that must not block a
session, log rotation."""

import subprocess
import sys
import time
from types import SimpleNamespace

import pytest
from agentbox import box as boxmod
from agentbox import cli, docker, mcpgw, term

PAYLOAD = "\x1b]0;PWNED\x07\x1b[2J\x1b[31mFAKE\x1b[0m"


def test_clean_payload():
    out = term.clean(PAYLOAD)
    assert "\x1b" not in out and "\x07" not in out
    assert out == "\\x1b]0;PWNED\\x07\\x1b[2J\\x1b[31mFAKE\\x1b[0m"
    assert term.clean("a\x9b31mb") == "a\\x9b31mb"  # C1 CSI
    assert term.clean("a\nb\tc") == "a\\x0ab\tc"
    assert term.clean("a\nb\rc", multiline=True) == "a\nb\\x0dc"
    assert term.clean("naïve ✔") == "naïve ✔"


def test_warn_and_err_are_clean(capsys):
    boxmod.warn(PAYLOAD + "\x9b")
    cli.err(PAYLOAD)
    e = capsys.readouterr().err
    assert "\x1b" not in e and "\x07" not in e and "\x9b" not in e and "PWNED" in e


def test_print_results_clean(capsys):
    from agentbox import doctor

    cli.print_results([doctor.Result("FAIL", "20 upstreams", "dead (" + PAYLOAD + ")")])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "FAKE" in out


def test_run_caps_output():
    t0 = time.monotonic()
    r = docker.run(["cat", "/dev/zero"], check=False, max_capture=1 << 20, timeout=30)
    assert r.returncode == docker.CAPPED_RC and len(r.stdout) <= 1 << 20
    assert time.monotonic() - t0 < 10


def test_run_timeout_kills_no_exception():
    t0 = time.monotonic()
    r = docker.run(["sleep", "30"], check=False, timeout=1)
    assert r.returncode == docker.TIMEOUT_RC and "timed out" in r.stderr
    assert time.monotonic() - t0 < 5
    with pytest.raises(docker.DockerError):
        docker.run(["sleep", "30"], timeout=1)


def test_run_text_and_input():
    r = docker.run([sys.executable, "-c", "import sys; print(sys.stdin.read().upper())"],
                   input="héllo")  # fmt: skip
    assert r.stdout == "HÉLLO\n" and r.returncode == 0


def test_no_home_config_io():
    """The CLI does not read or write agent config files at all (Codex: launch
    overrides; Pi: root-owned /etc/agentbox/pi-mcp.json)."""
    for name in ("agent_mcp_configs", "READ_FILE", "WRITE_FILE", "CLIENT_CONFIGS"):
        assert not hasattr(boxmod, name)
    assert not hasattr(mcpgw, "merge_codex") and not hasattr(mcpgw, "merge_pi")


def test_run_stdin_child_never_reads():
    """Large input to a child that never reads stdin: the timeout still fires."""
    t0 = time.monotonic()
    r = docker.run(["sleep", "30"], check=False, input="x" * (8 << 20), timeout=2)
    assert r.returncode == docker.TIMEOUT_RC
    assert time.monotonic() - t0 < 6


def test_rotate_egress_log(tmp_path, monkeypatch):
    d = tmp_path / "logs" / "egress"
    d.mkdir(parents=True)
    ctx = SimpleNamespace(egress_logs=d)
    calls = []
    monkeypatch.setattr(boxmod, "dc", lambda b, *a, **k: calls.append(a) or
                        subprocess.CompletedProcess(a, 0, "", ""))  # fmt: skip
    (d / "egress.log").write_text("x" * 100)
    assert boxmod.rotate_egress_log(None, ctx, max_bytes=1000) is False and not calls
    (d / "egress.log.1").write_text("old")
    assert boxmod.rotate_egress_log(None, ctx, max_bytes=10) is True
    assert (d / "egress.log.1").read_text() == "x" * 100 and not (d / "egress.log").exists()
    assert calls == [("exec", "-T", "egress", "squid", "-k", "rotate", "-f", boxmod.SQUID_CONF)]
    assert boxmod.rotate_egress_log(None, ctx, max_bytes=10) is False  # no file: nothing


def test_gate_log_rotates(tmp_path):
    sys.path.insert(0, str(__import__("pathlib").Path(__file__).resolve().parents[2]
                           / "images" / "ollama-gate"))  # fmt: skip
    import gate

    log = tmp_path / "g.log"
    g = gate.Gate.__new__(gate.Gate)
    import threading

    g._log_lock, g._log_path = threading.Lock(), str(log)
    g._log = open(log, "a", buffering=1)  # noqa: SIM115
    g.LOG_MAX = 200
    for i in range(20):
        g.log(event="x", i=i)
    assert (tmp_path / "g.log.1").is_file() and log.stat().st_size <= 260
    g._log.close()
