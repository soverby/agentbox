"""Parse the egress access log for the agent's denied requests (PLAN §2.2).

Squid native log format: time elapsed client code/status bytes method URL ...
"""

from __future__ import annotations

import re
import time
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime

from .allowedit import domain_problem

SINCE_RE = re.compile(r"(\d+)([smhd])")


class DeniedError(Exception):
    pass


@dataclass
class Denial:
    host: str
    count: int = 0
    first: float = 0.0
    last: float = 0.0
    ports: set[str] = field(default_factory=set)
    allowable: bool = True  # a valid allowlist hostname (not an IP or local name)
    reason: str = ""

    def as_json(self) -> dict:
        return {
            "host": self.host,
            "count": self.count,
            "first": datetime.fromtimestamp(self.first).astimezone().isoformat(timespec="seconds"),
            "last": datetime.fromtimestamp(self.last).astimezone().isoformat(timespec="seconds"),
            "ports": sorted(self.ports, key=lambda p: (len(p), p)),
            "allowable": self.allowable,
            "reason": self.reason,
        }


def parse_since(s: str, now: float | None = None) -> float:
    """`30m`, `2h`, `1d`, `45s`, or an ISO date/datetime (local time if naive)."""
    now = time.time() if now is None else now
    m = SINCE_RE.fullmatch(s)
    if m:
        return now - int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]
    try:
        dt = datetime.fromisoformat(s)
    except ValueError:
        raise DeniedError(f"--since {s!r}: use 30m, 2h, 1d, or an ISO date/time") from None
    return dt.timestamp() if dt.tzinfo else dt.astimezone().timestamp()


def user_agent(fields: list[str]) -> str | None:
    """The agentbox logformat's last field: "<url-encoded UA>" (None: old format)."""
    if len(fields) < 11:
        return None
    q = fields[10]
    if len(q) < 2 or q[0] != '"' or q[-1] != '"':
        return None
    return urllib.parse.unquote(q[1:-1])


def host_port(method: str, url: str) -> tuple[str, str] | None:
    if method == "CONNECT":
        host, _, port = url.rpartition(":")
        if not host:
            return None
        return host.strip("[]").lower(), port
    parts = urllib.parse.urlsplit(url)
    if not parts.hostname:
        return None
    try:
        port = str(parts.port or (443 if parts.scheme == "https" else 80))
    except ValueError:
        port = "?"
    return parts.hostname.lower(), port


def allow_matches(host: str, allowlist: list[str]) -> bool:
    """Squid dstdomain semantics: `a.b` exact; `.a.b` = a.b and subdomains."""
    for e in allowlist:
        e = e.lower()
        if e.startswith("."):
            if host == e[1:] or host.endswith(e):
                return True
        elif host == e:
            return True
    return False


def parse(
    lines,
    client_ip: str,
    allowlist: list[str] | None = None,
    since: float = 0.0,
    exclude: list[tuple[float, float, str]] = (),
) -> list[Denial]:
    """Unique denied hosts from `client_ip`, allowable first, then most frequent.

    `exclude`: (start, end, user_agent) of doctor runs. A line is dropped only
    when its User-Agent equals that run's nonce UA AND its time is in that
    run's window; other traffic in the window stays visible. Lines in the old
    native format (no UA field) are never dropped.
    """
    out: dict[str, Denial] = {}
    for line in lines:
        f = line.split()
        if len(f) < 7 or f[2] != client_ip or not f[3].startswith("TCP_DENIED"):
            continue
        try:
            ts = float(f[0])
        except ValueError:
            continue
        if ts < since:
            continue
        ua = user_agent(f)
        if ua is not None and any(u == ua and a <= ts <= z for a, z, u in exclude):
            continue
        hp = host_port(f[5], f[6])
        if hp is None:
            continue
        host, port = hp
        d = out.get(host)
        if d is None:
            d = out[host] = Denial(host, first=ts)
            problem = domain_problem(host)
            if problem:
                d.allowable, d.reason = False, problem
            elif allowlist is not None and allow_matches(host, allowlist):
                d.allowable, d.reason = (
                    False,
                    "on the allowlist now (added later, or denied by port)",
                )
            else:
                d.reason = "not on the allowlist"
        d.count += 1
        d.last = max(d.last, ts)
        d.ports.add(port)
    return sorted(out.values(), key=lambda d: (not d.allowable, -d.count, d.host))
