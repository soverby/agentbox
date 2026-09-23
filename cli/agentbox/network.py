"""Per-profile internal subnet allocation and fixed IPs (PLAN §2).

Each profile gets `<base>.<n>.0/24` with n in 1..254. `n` is stored in
`<state_root>/<profile>/subnet`. Allocation takes the lowest free n, so freed
values are reused.
"""

from __future__ import annotations

import fcntl
import ipaddress
from contextlib import contextmanager
from pathlib import Path

DEFAULT_BASE = "10.213.0.0/16"
N_MIN, N_MAX = 1, 254
SUBNET_FILE = "subnet"
LOCK_FILE = ".subnet.lock"

# Host part of the fixed IP per service in the /24. .1 is the Docker gateway
# address (reserved by Docker even on `internal: true` networks).
SERVICE_HOSTS = {
    "egress": 2,
    "agent": 10,
    "router": 11,
    "mcp-gateway": 12,
    "ollama-gate": 13,
}


class NetworkError(Exception):
    pass


def parse_base(base: str) -> ipaddress.IPv4Network:
    """Base must be a private IPv4 /16 (for example 10.213.0.0/16)."""
    try:
        net = ipaddress.IPv4Network(base, strict=True)
    except ValueError as e:
        raise NetworkError(f"subnet base {base!r}: {e}") from None
    if net.prefixlen != 16:
        raise NetworkError(f"subnet base {base!r} must be a /16")
    if not net.is_private:
        raise NetworkError(f"subnet base {base!r} must be a private range")
    return net


def subnet_for(n: int, base: str = DEFAULT_BASE) -> ipaddress.IPv4Network:
    if not N_MIN <= n <= N_MAX:
        raise NetworkError(f"subnet index {n} out of range {N_MIN}..{N_MAX}")
    b = parse_base(base)
    return ipaddress.IPv4Network((int(b.network_address) + (n << 8), 24))


def _read_n(path: Path) -> int:
    text = path.read_text().strip()
    if not text.isdigit() or not N_MIN <= int(text) <= N_MAX:
        raise NetworkError(f"{path}: invalid subnet index {text!r}")
    return int(text)


@contextmanager
def _locked(state_root: Path):
    state_root.mkdir(parents=True, exist_ok=True)
    with (state_root / LOCK_FILE).open("w") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


def used_indexes(state_root: Path) -> dict[int, str]:
    """n -> profile for every profile state dir that holds a subnet file."""
    used: dict[int, str] = {}
    if not state_root.is_dir():
        return used
    for d in sorted(state_root.iterdir()):
        f = d / SUBNET_FILE
        if d.is_dir() and f.is_file():
            n = _read_n(f)
            if n in used:
                raise NetworkError(f"subnet index {n} used by {used[n]} and {d.name}")
            used[n] = d.name
    return used


def _entries(in_use, exclude_project: str | None):
    """Normalize `in_use` items: a CIDR string, or a (project, CIDR) pair where
    project is the Compose project label ("" for none)."""
    for item in in_use:
        if isinstance(item, str):
            yield item
        elif isinstance(item, tuple) and len(item) == 2:
            project, cidr = item
            if exclude_project is None or project != exclude_project:
                yield cidr
        else:
            raise NetworkError(f"invalid in-use entry {item!r}")


def colliding_indexes(
    in_use, base: str = DEFAULT_BASE, exclude_project: str | None = None
) -> set[int]:
    """Indexes whose /24 overlaps any subnet in `in_use` (every IPAM subnet
    Docker reports). Entries of `exclude_project` are ignored. Pure; invalid
    entries are an error."""
    nets = []
    for s in _entries(in_use, exclude_project):
        try:
            nets.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            raise NetworkError(f"invalid in-use subnet {s!r}") from None
    return {
        n for n in range(N_MIN, N_MAX + 1) if any(subnet_for(n, base).overlaps(x) for x in nets)
    }


def verify(n: int, in_use, base: str = DEFAULT_BASE, exclude_project: str | None = None) -> None:
    """At every `up`: error when the profile's subnet overlaps a subnet in use.
    Pass `exclude_project` = the profile's own Compose project, so a re-`up` of
    a running box (its own network already exists) passes."""
    if n in colliding_indexes(in_use, base, exclude_project):
        raise NetworkError(
            f"subnet {subnet_for(n, base)} overlaps an existing Docker network; "
            "remove that network or change the subnet base"
        )


def allocate(state_root: str | Path, profile: str, in_use=(), base: str = DEFAULT_BASE) -> int:
    """Return the profile's subnet index; allocate the lowest free one if none.

    `in_use`: subnets that already exist (for example Docker's); indexes that
    overlap them are skipped. An existing allocation is returned unchanged
    (check it with `verify`).
    """
    root = Path(state_root)
    with _locked(root):
        f = root / profile / SUBNET_FILE
        if f.is_file():
            return _read_n(f)
        taken = set(used_indexes(root)) | colliding_indexes(in_use, base, exclude_project=None)
        for n in range(N_MIN, N_MAX + 1):
            if n not in taken:
                f.parent.mkdir(parents=True, exist_ok=True)
                tmp = f.with_suffix(".tmp")
                tmp.write_text(f"{n}\n")
                tmp.replace(f)
                return n
        raise NetworkError(f"no free subnet index ({N_MIN}..{N_MAX} all used)")


def release(state_root: str | Path, profile: str) -> None:
    """Free the profile's subnet index (idempotent)."""
    root = Path(state_root)
    with _locked(root):
        (root / profile / SUBNET_FILE).unlink(missing_ok=True)


def fixed_ips(n: int, base: str = DEFAULT_BASE) -> dict[str, str]:
    net = subnet_for(n, base)
    return {svc: str(net.network_address + h) for svc, h in SERVICE_HOSTS.items()}


def gateway_ip(n: int, base: str = DEFAULT_BASE) -> str:
    return str(subnet_for(n, base).network_address + 1)
