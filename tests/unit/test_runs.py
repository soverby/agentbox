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
