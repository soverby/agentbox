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
    """Create a fresh run dir atomically: mkdir, and on FileExistsError try the
    next suffix (two fires in the same UTC second never share a dir)."""
    base = f"{stamp(now)}-{agent}"
    runs_root.mkdir(parents=True, exist_ok=True)
    for i in range(1, 10000):
        d = runs_root / (base if i == 1 else f"{base}-{i}")
        try:
            d.mkdir(mode=0o700)
            return d
        except FileExistsError:
            continue
    raise FileExistsError(f"no free run dir name for {base} in {runs_root}")


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


TRANSCRIPT_CAP = 50 * 1024 * 1024
RUNS_KEEP = 200
TRUNC_MARK = "\n[agentbox: transcript truncated at {cap} bytes; the run went on]\n"


def copy_capped(src, dst, cap: int = TRANSCRIPT_CAP) -> int:
    """Copy src to dst up to cap bytes, then one marker line; drain the rest
    (so the writer never blocks). Returns the bytes read."""
    total, cut = 0, False
    while chunk := src.read1(65536) if hasattr(src, "read1") else src.read(65536):
        room = cap - total
        total += len(chunk)
        if cut:
            continue
        if len(chunk) <= room:
            dst.write(chunk)
        else:
            dst.write(chunk[:room])
            dst.write(TRUNC_MARK.format(cap=cap).encode())
            cut = True
        dst.flush()
    return total


def prune(runs_root: Path, keep: int, current: Path | None = None) -> list[Path]:
    """Delete the oldest run dirs beyond `keep` (names start with a UTC stamp)."""
    import shutil

    dirs = sorted(p for p in runs_root.iterdir() if p.is_dir()) if runs_root.is_dir() else []
    old = [p for p in dirs[: max(0, len(dirs) - keep)] if p != current]
    for p in old:
        shutil.rmtree(p, ignore_errors=True)
    return old


RUN_ENV = "AGENTBOX_RUN"


def kill_script(run_id: str) -> str:
    """sh: SIGKILL every process in the box whose environment has AGENTBOX_RUN=<id>."""
    return (
        'for p in /proc/[0-9]*; do tr "\\0" "\\n" < "$p/environ" 2>/dev/null '
        f'| grep -qx "{RUN_ENV}={run_id}" && kill -KILL "${{p#/proc/}}" 2>/dev/null; done; true'
    )
