"""Headless run bookkeeping."""

import json
from datetime import UTC, datetime

from agentbox import runs


def test_run_dir_and_record(tmp_path):
    now = datetime(2026, 9, 23, 7, 0, 5, tzinfo=UTC)
    d1 = runs.new_run_dir(tmp_path, "claude", now)
    d2 = runs.new_run_dir(tmp_path, "claude", now)
    assert d1.name == "20260923T070005Z-claude" and d2.name == "20260923T070005Z-claude-2"
    assert d1.stat().st_mode & 0o777 == 0o700
    t = runs.transcript_path(d1)
    assert t.stat().st_mode & 0o777 == 0o600
    runs.finish(d1, 3, {"agent": "claude", "profile": "p"})
    assert (d1 / "exit_code").read_text() == "3\n"
    meta = json.loads((d1 / "meta.json").read_text())
    assert meta["exit_code"] == 3 and meta["agent"] == "claude" and "finished" in meta


def test_prompt_digest():
    assert runs.prompt_digest("x") == (
        "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    )


def test_copy_capped():
    import io

    from agentbox import runs

    out = io.BytesIO()
    n = runs.copy_capped(io.BufferedReader(io.BytesIO(b"a" * 100)), out, cap=10)
    assert n == 100
    assert out.getvalue() == b"a" * 10 + runs.TRUNC_MARK.format(cap=10).encode()
    out = io.BytesIO()
    runs.copy_capped(io.BufferedReader(io.BytesIO(b"abc")), out, cap=10)
    assert out.getvalue() == b"abc"


def test_kill_script_targets_run_env():
    from agentbox import runs

    s = runs.kill_script("20260101T000000Z-claude")
    assert "AGENTBOX_RUN=20260101T000000Z-claude" in s and "kill -KILL" in s


def test_kill_all_script_spares_init_and_main(tmp_path):
    """Run the script against a fake /proc: only leftovers get SIGKILL."""
    import subprocess

    from agentbox import runs

    proc = tmp_path / "proc"
    for pid, ppid, cmd in (
        (1, 0, b"/sbin/docker-init\0--\0sleep\0infinity\0"),
        (7, 1, b"sleep\0infinity\0"),
        (50, 1, b"sh\0-c\0while :; do sleep 1; done\0"),
        (51, 0, b"\0"),  # argv wiped: still killed
    ):
        d = proc / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(cmd)
        (d / "status").write_text(f"Name:\tx\nPPid:\t{ppid}\n")
    s = runs.kill_all_script().replace("/proc/", f"{proc}/")
    log = tmp_path / "killed"
    s = s.replace('kill -KILL "$n"', f'echo "$n" >> {log}')
    subprocess.run(["sh", "-c", s], check=True)
    assert sorted(log.read_text().split()) == ["50", "51"]


def test_runs_keep_config(tmp_path, monkeypatch):
    import pytest
    from agentbox import paths

    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    assert paths.load_config().runs_keep == 200
    (tmp_path / "config.toml").write_text('runs_keep = "5"\n')
    assert paths.load_config().runs_keep == 5
    (tmp_path / "config.toml").write_text('runs_keep = "0"\n')
    with pytest.raises(paths.ConfigError):
        paths.load_config()


def test_new_run_dir_same_second_no_collision(tmp_path):
    import threading
    from datetime import UTC, datetime

    from agentbox import runs

    now = datetime(2026, 1, 1, tzinfo=UTC)
    out, errs = [], []

    def mk():
        try:
            out.append(runs.new_run_dir(tmp_path, "claude", now))
        except Exception as e:  # noqa: BLE001
            errs.append(e)

    ts = [threading.Thread(target=mk) for _ in range(20)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert not errs and len({p.name for p in out}) == 20
    # a dir that appears between check and create is skipped, not an error
    (tmp_path / "x").mkdir()
    assert runs.new_run_dir(tmp_path / "x", "pi", now).name == "20260101T000000Z-pi"
    assert runs.new_run_dir(tmp_path / "x", "pi", now).name == "20260101T000000Z-pi-2"
