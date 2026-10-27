"""Fire hook (PLAN §2.7).

At the end of every fire that notifications cover, the host runs the command
that `fire_command` in config.toml names. The command gets the fire's outcome
as JSON on stdin. It runs with no shell, `cwd` `/`, in its own session, and
with the fire's own environment plus AGENTBOX_FIRE_HOOK=1 (the recursion
guard, cli.py). agentbox adds no secret to the environment or the payload.

The command has a time limit. At the limit, or when a signal or an error
interrupts the fire, the CLI sends SIGKILL to the command's process group. The
CLI also kills the group after the command exits, so a hook leaves no
background process behind. A failure never raises and never changes the exit
code: the result is "ok" or "error: <reason>".

`detail` and `message` in the payload are untrusted box output, not scrubbed of
secret values.
"""

from __future__ import annotations

import contextlib
import json
import os
import signal
import subprocess
import threading

from . import notify, paths

HOOK_ENV = "AGENTBOX_FIRE_HOOK"
HOOK_LIMIT = 30.0  # seconds
TERMINATED_LIMIT = notify.TERMINATED_TIMEOUT  # after SIGTERM: launchd kills us soon
STDERR_CAP = 64 * 1024  # bytes of stderr kept (the end), for the failure reason only
EOF_WAIT = 1.0  # seconds to wait for stderr EOF after the command exits
VERSION = 1
# Keys that every payload has. A key that the record lacks (a skipped fire has
# no run_dir) is null; `warnings` is [].
PAYLOAD_KEYS = ("profile", "name", "kind", "agent", "trigger", "start", "end", "status",
                "exit_code", "message", "warnings", "run_dir", "transcript")  # fmt: skip


# A signal that arrives while Popen forks and execs must not unwind there: `p`
# would still be None, and the child would run on with no limit and no kill.
# The CLI's signal handler calls defer_signal(); while Popen runs it records the
# signal, and run() raises it as Terminated once `p` is set. (No signal mask:
# the child would inherit it.)
_in_popen = False
_pending: int | None = None


def defer_signal(signum: int) -> bool:
    """True: the signal is recorded for run() and the handler must not raise."""
    global _pending
    if not _in_popen:
        return False
    _pending = signum
    return True


def _raise_pending() -> None:
    global _pending
    if _pending is not None:
        signum, _pending = _pending, None
        from .schedule import Terminated  # not at import: schedule imports this module

        raise Terminated(signum)


def _why(e: BaseException) -> str:
    signum = getattr(e, "signum", None)  # schedule.Terminated
    if isinstance(signum, int):
        return f"terminated by signal {signum}"
    return notify.clean_line(f"{type(e).__name__}: {e}", notify.REASON_CAP)


def build_payload(rec: dict, *, outcome: str, seconds: float, detail: str) -> dict:
    """The record as `last.json` (or `skipped.json`) holds it now, every key,
    plus version, outcome, seconds, and detail."""
    out: dict = dict.fromkeys(PAYLOAD_KEYS)
    out.update(rec)
    if out["warnings"] is None:
        out["warnings"] = []
    out.update(version=VERSION, outcome=outcome, seconds=round(seconds, 3), detail=detail)
    return out


def _kill_group(p: subprocess.Popen) -> None:
    with contextlib.suppress(OSError):  # the group is gone already
        os.killpg(p.pid, signal.SIGKILL)


def _feed(stream, body: bytes) -> None:
    """Write the payload, then close stdin. A command that does not read it
    gets a broken pipe when the group is killed."""
    try:
        stream.write(body)
    except OSError:
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _drain(stream, buf: bytearray) -> None:
    """Read stderr to EOF; keep the last STDERR_CAP bytes."""
    try:
        while chunk := stream.read1(4096):
            buf += chunk
            if len(buf) > STDERR_CAP:
                del buf[:-STDERR_CAP]
    except (OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(OSError):
            stream.close()


def _stderr_line(buf: bytearray) -> str:
    """Last non-empty stderr line, cleaned, at most REASON_CAP characters."""
    for raw in reversed(bytes(buf).decode("utf-8", "replace").splitlines()):
        if line := notify.clean_line(raw, notify.REASON_CAP):
            return line
    return ""


def run(argv, payload: dict, outcome: str) -> str:
    """Run the hook. "ok" or "error: <reason>". Never raises an Exception. A
    SystemExit or KeyboardInterrupt kills the group, then is raised again."""
    limit = TERMINATED_LIMIT if outcome == "terminated" else HOOK_LIMIT
    global _in_popen, _pending
    err = bytearray()
    p = None
    why = None
    try:
        body = (json.dumps(payload, sort_keys=True) + "\n").encode()
        env = {**os.environ, HOOK_ENV: "1"}
        _pending = None
        try:
            _in_popen = True
            try:
                p = subprocess.Popen(
                    list(argv), stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE, cwd="/", env=env, start_new_session=True,
                )  # fmt: skip
            finally:
                _in_popen = False
        except OSError as e:
            if _pending is not None:  # the fire was stopped during the failed start
                signum, _pending = _pending, None
                return f"error: terminated by signal {signum}"
            return "error: " + notify.clean_line(
                f"cannot start: {e.strerror or e}", notify.REASON_CAP
            )
        _raise_pending()  # a signal that came during Popen: the except below kills the group
        feeder = threading.Thread(target=_feed, args=(p.stdin, body), daemon=True)
        reader = threading.Thread(target=_drain, args=(p.stderr, err), daemon=True)
        feeder.start()
        reader.start()
        try:
            code = p.wait(timeout=limit)
        except subprocess.TimeoutExpired:
            code = None
            why = f"ran over the {limit:.0f} s limit"
            _kill_group(p)
            with contextlib.suppress(subprocess.TimeoutExpired):
                p.wait(timeout=EOF_WAIT)
        reader.join(EOF_WAIT)  # a grandchild that holds stderr cannot hold the fire
        _kill_group(p)  # no background process stays
        reader.join(EOF_WAIT)
        if why is None and code == 0:
            return "ok"
        if why is None:
            assert code is not None
            why = f"exit code {code}" if code > 0 else f"terminated by signal {-code}"
    except BaseException as e:  # noqa: BLE001 - reported, never raised
        if p is not None:
            _kill_group(p)
        if not isinstance(e, Exception):
            raise
        why = _why(e)
    tail = _stderr_line(err)
    return f"error: {why}" + (f": {tail}" if tail else "")


def fire_hook(
    rec: dict, *, outcome: str, seconds: float, transcript, note: str | None
) -> str | None:
    """None: no hook is set (nothing done, no process). Else "ok" or
    "error: <reason>". Never raises an Exception: a Terminated at any point
    (config read, detail read, the run) is "error: terminated by signal N"."""
    try:
        cfg = paths.load_config()
    except Exception as e:  # noqa: BLE001 - notify_fire reports an unreadable config
        # A signal is not a config problem: the hook did not run.
        return f"error: {_why(e)}" if isinstance(getattr(e, "signum", None), int) else None
    if cfg.fire_command is None:
        return None
    try:
        detail = notify.detail_text(outcome, transcript, note)
        payload = build_payload(rec, outcome=outcome, seconds=seconds, detail=detail)
        return run(cfg.fire_command, payload, outcome)
    except Exception as e:  # noqa: BLE001 - a hook must not fail the fire
        return f"error: {_why(e)}"
