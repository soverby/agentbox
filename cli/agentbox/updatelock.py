"""The update lock (PLAN §2.9).

Every apply path of `agentbox update` holds the exclusive flock
`<state>/_update/update.lock`. While it is held, `schedule _fire` waits and
then records `not_run`, and every command that starts a box exits 75.

The holder passes the check (it must start its own scratch doctor box): an
in-process flag, set only while this process holds the lock. A fire, another
CLI process, or a shell never passes; no environment variable carries it.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import time
from pathlib import Path

from . import paths

UPDATE_DIR = "_update"
RC_BUSY = 75  # EX_TEMPFAIL
BUSY_MSG = "an update is running; retry in a few minutes"
ANOTHER_MSG = "another update is running; retry in a few minutes"


class UpdateBusy(Exception):
    """An update holds the lock. The CLI exits 75 with this message."""


_HOLDER = False


def update_dir() -> Path:
    """`<state>/_update/`, mode 0700 (made like the fleet report dir)."""
    root = paths.state_home()
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    d = root / UPDATE_DIR
    d.mkdir(exist_ok=True, mode=0o700)
    os.chmod(d, 0o700)
    return d


def lock_file() -> Path:
    return paths.state_home() / UPDATE_DIR / "update.lock"


HOLD_TRIES = 10
HOLD_PAUSE = 0.1  # seconds: about 1 s in total before UpdateBusy


def holder() -> bool:
    """True inside the process that holds the lock."""
    return _HOLDER


@contextlib.contextmanager
def hold():
    """Take the exclusive lock, or raise UpdateBusy. Sets the holder flag."""
    global _HOLDER
    if _HOLDER:
        raise UpdateBusy(ANOTHER_MSG)
    f = update_dir() / "update.lock"
    with f.open("a") as lk:
        os.chmod(f, 0o600)
        for attempt in range(HOLD_TRIES):  # a busy() probe holds LOCK_SH for microseconds
            try:
                fcntl.flock(lk, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if attempt == HOLD_TRIES - 1:
                    raise UpdateBusy(ANOTHER_MSG) from None
                time.sleep(HOLD_PAUSE)
        _HOLDER = True
        try:
            yield
        finally:
            _HOLDER = False


def busy() -> bool:
    """True when another process holds the lock. False for the holder, and
    when there is no lock file (nothing to hold, nothing created)."""
    if _HOLDER:
        return False
    try:
        with lock_file().open("rb") as lk:
            try:
                # Shared: two probes do not block each other; only hold()'s exclusive lock does.
                fcntl.flock(lk, fcntl.LOCK_SH | fcntl.LOCK_NB)
            except BlockingIOError:
                return True
            fcntl.flock(lk, fcntl.LOCK_UN)
            return False
    except OSError:
        return False


def check() -> None:
    """Raise UpdateBusy when an update runs (the box-start interlock)."""
    if busy():
        raise UpdateBusy(BUSY_MSG)
