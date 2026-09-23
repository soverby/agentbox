"""Thin wrappers around the docker CLI. Every call goes through `run`, so
tests can replace it."""

from __future__ import annotations

import subprocess
from pathlib import Path


class DockerError(Exception):
    pass


def run(
    args: list[str],
    *,
    check: bool = True,
    input: str | None = None,
    capture: bool = True,
    timeout: float | None = None,
    env: dict | None = None,
    cwd: str | Path | None = None,
) -> subprocess.CompletedProcess:
    try:
        r = subprocess.run(
            args,
            input=input,
            capture_output=capture,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
    except FileNotFoundError:
        raise DockerError(f"{args[0]}: command not found") from None
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
