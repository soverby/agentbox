"""Headless run bookkeeping (PLAN §2.3 `run`): <state>/runs/<timestamp>-<agent>/
with transcript.log, exit_code, meta.json."""

from __future__ import annotations

import hashlib
import json
import os
from datetime import UTC, datetime
from pathlib import Path


def stamp(now: datetime | None = None) -> str:
    now = now or datetime.now(UTC)
    return now.astimezone(UTC).strftime("%Y%m%dT%H%M%SZ")


def new_run_dir(runs_root: Path, agent: str, now: datetime | None = None) -> Path:
    base = f"{stamp(now)}-{agent}"
    d = runs_root / base
    i = 2
    while d.exists():
        d = runs_root / f"{base}-{i}"
        i += 1
    d.mkdir(parents=True, mode=0o700)
    return d


def write_meta(run_dir: Path, **meta) -> None:
    f = run_dir / "meta.json"
    tmp = f.with_suffix(".tmp")
    tmp.write_text(json.dumps(meta, indent=1, sort_keys=True) + "\n")
    tmp.replace(f)


def finish(run_dir: Path, exit_code: int, meta: dict) -> None:
    (run_dir / "exit_code").write_text(f"{exit_code}\n")
    write_meta(run_dir, **meta, exit_code=exit_code,
               finished=datetime.now(UTC).isoformat(timespec="seconds"))  # fmt: skip


def prompt_digest(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()


def transcript_path(run_dir: Path) -> Path:
    p = run_dir / "transcript.log"
    p.touch(mode=0o600)
    os.chmod(p, 0o600)
    return p
