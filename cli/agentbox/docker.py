"""Thin wrappers around the docker CLI. Every call goes through `run`, so
tests can replace it."""

from __future__ import annotations

import contextlib
import subprocess
import threading
import time
from pathlib import Path


class DockerError(Exception):
    pass


# Captured output cap per stream. Output from the box is agent-controlled: a
# `cat` of /dev/zero must not fill host memory.
MAX_CAPTURE = 16 * 1024 * 1024
TIMEOUT_RC = 124
CAPPED_RC = 125


def _pump(stream, buf: bytearray, cap: int, over: threading.Event) -> None:
    while chunk := stream.read(65536):
        room = cap - len(buf)
        if room > 0:
            buf += chunk[:room]
        if len(chunk) > room:
            over.set()
            break
    stream.close()


def _feed(stream, data: bytes) -> None:
    try:
        stream.write(data)
    except (BrokenPipeError, OSError, ValueError):
        pass
    finally:
        with contextlib.suppress(BrokenPipeError, OSError):
            stream.close()


def _run_capped(args, input, timeout, env, cwd, cap):
    """subprocess.run(capture_output=True, text=True) with a size cap per
    stream and a timeout that kills the child instead of raising."""
    try:
        p = subprocess.Popen(
            args,
            stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise DockerError(f"{args[0]}: command not found") from None
    out, err, over = bytearray(), bytearray(), threading.Event()
    threads = [
        threading.Thread(target=_pump, args=(p.stdout, out, cap, over), daemon=True),
        threading.Thread(target=_pump, args=(p.stderr, err, cap, over), daemon=True),
    ]
    for t in threads:
        t.start()
    if input is not None:  # own thread: a child that never reads stdin cannot block the loop
        threads.append(threading.Thread(target=_feed, args=(p.stdin, input.encode()), daemon=True))
        threads[-1].start()
    deadline = None if timeout is None else time.monotonic() + timeout
    rc = None
    while rc is None:
        try:
            rc = p.wait(timeout=0.1)
        except subprocess.TimeoutExpired:
            if over.is_set():
                p.kill()
                p.wait()
                rc = CAPPED_RC
                err += f"\nagentbox: output over {cap} bytes, command killed".encode()
            elif deadline is not None and time.monotonic() > deadline:
                p.kill()
                p.wait()
                rc = TIMEOUT_RC
                err += f"\nagentbox: timed out after {timeout:.0f}s, command killed".encode()
    for t in threads:
        t.join(timeout=5)
    if over.is_set() and rc != CAPPED_RC:  # e.g. SIGPIPE after the pump stopped
        rc = CAPPED_RC
        err += f"\nagentbox: output over {cap} bytes, command killed".encode()
    dec = lambda b: bytes(b).decode("utf-8", "replace")  # noqa: E731
    return subprocess.CompletedProcess(args, rc, dec(out), dec(err))


def run(
    args: list[str],
    *,
    check: bool = True,
    input: str | None = None,
    capture: bool = True,
    timeout: float | None = None,
    env: dict | None = None,
    cwd: str | Path | None = None,
    max_capture: int = MAX_CAPTURE,
) -> subprocess.CompletedProcess:
    """Run a command. Captured output is capped at `max_capture` bytes per
    stream (over the cap: the command is killed, rc 125); a timeout kills it
    (rc 124) instead of raising. No input: stdin is /dev/null (inheriting it
    let `docker compose exec -T` during `up` swallow the stdin of the session
    command that follows)."""
    if capture:
        r = _run_capped(args, input, timeout, env, cwd, max_capture)
    else:
        stdin = {"input": input} if input is not None else {"stdin": subprocess.DEVNULL}
        try:
            r = subprocess.run(args, **stdin, text=True, timeout=timeout, env=env, cwd=cwd)
        except FileNotFoundError:
            raise DockerError(f"{args[0]}: command not found") from None
        except subprocess.TimeoutExpired:
            raise DockerError(f"{' '.join(map(str, args))} timed out after {timeout}s") from None
    if check and r.returncode != 0:
        detail = ((r.stderr or "") + (r.stdout or "")).strip()[-2000:] if capture else ""
        raise DockerError(f"{' '.join(map(str, args))} failed ({r.returncode}): {detail}")
    return r


def image_id(ref: str) -> str | None:
    r = run(["docker", "image", "inspect", "--format", "{{.Id}}", ref], check=False)
    return r.stdout.strip() if r.returncode == 0 else None


def subnets() -> list[tuple[str, str]]:
    """(compose project label, subnet) for every IPAM subnet Docker uses."""
    ids = run(["docker", "network", "ls", "-q"]).stdout.split()
    if not ids:
        return []
    out = run(
        [
            "docker",
            "network",
            "inspect",
            *ids,
            "--format",
            '{{index .Labels "com.docker.compose.project"}}|'
            "{{range .IPAM.Config}}{{.Subnet}} {{end}}",
        ]
    ).stdout
    return [
        (proj, cidr)
        for proj, _, nets in (line.partition("|") for line in out.splitlines())
        for cidr in nets.split()
    ]


def running_projects(prefix: str = "agentbox-") -> dict[str, list[str]]:
    """Compose project -> running service names, for projects with `prefix`."""
    out = run(
        [
            "docker",
            "ps",
            "--filter",
            "label=com.docker.compose.project",
            "--format",
            '{{.Label "com.docker.compose.project"}}|{{.Label "com.docker.compose.service"}}',
        ]
    ).stdout
    res: dict[str, list[str]] = {}
    for line in out.splitlines():
        proj, _, svc = line.partition("|")
        if proj.startswith(prefix):
            res.setdefault(proj, []).append(svc)
    return res
