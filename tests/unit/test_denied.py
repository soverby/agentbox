"""Denied-log parsing on real egress log lines from a P2 harness run."""

from pathlib import Path

import pytest
from agentbox import denied

LOG = (Path(__file__).parent / "data" / "p2-egress.log").read_text().splitlines()
AGENT, ROUTER = "10.213.1.10", "10.213.1.11"
ALLOW = ["example.com", "one.one.one.one", ".github.com"]


def by_host(items):
    return {d.host: d for d in items}


def test_agent_denials():
    items = denied.parse(LOG, AGENT, ALLOW)
    h = by_host(items)
    assert h["example.org"].count == 1 and h["example.org"].allowable
    assert h["example.org"].ports == {"443"}
    assert h["www.wikipedia.org"].allowable  # denied before the live reload
    assert not h["1.1.1.1"].allowable and "IP" in h["1.1.1.1"].reason
    assert not h["host.docker.internal"].allowable
    assert h["host.docker.internal"].ports >= {"80", "443", "22", "11434"}
    assert not h["2606:4700:4700::1111"].allowable
    assert not h["egress"].allowable
    # tunnels (TCP_TUNNEL/200) are not denials; other sources are ignored
    assert "example.net" not in h
    # allowable domains sort first
    assert items[0].allowable and not items[-1].allowable


def test_allowed_domain_denied_by_port():
    lines = [
        "1790159870.1 0 10.213.1.10 TCP_DENIED/403 3348 CONNECT example.com:22 - "
        "HIER_NONE/- text/html"
    ]
    d = denied.parse(lines, AGENT, ALLOW)[0]
    assert not d.allowable and "on the allowlist" in d.reason
    sub = lines[0].replace("example.com:22", "api.github.com:443")
    assert "on the allowlist" in denied.parse([sub], AGENT, ALLOW)[0].reason


def test_other_client_and_since():
    r = by_host(denied.parse(LOG, ROUTER, []))
    assert "example.com" in r and "example.org" not in r
    first_ts = float(LOG[0].split()[0])
    assert denied.parse(LOG, AGENT, ALLOW, since=first_ts + 10**6) == []


def test_garbage_lines_ignored():
    lines = ["", "garbage", "x y 10.213.1.10 TCP_DENIED/403 1 CONNECT a.com:443", *LOG[:3]]
    assert [d.host for d in denied.parse(lines, AGENT)] == ["example.org"]


def test_since_parse():
    assert denied.parse_since("30m", now=10000.0) == 10000.0 - 1800
    assert denied.parse_since("2h", now=10000.0) == 10000.0 - 7200
    assert denied.parse_since("1d", now=100000.0) == 100000.0 - 86400
    assert denied.parse_since("2026-09-23T10:00:00+00:00") == 1790157600.0
    with pytest.raises(denied.DeniedError):
        denied.parse_since("yesterday")


def test_json_shape():
    j = denied.parse(LOG, AGENT, ALLOW)[0].as_json()
    assert set(j) == {"host", "count", "first", "last", "ports", "allowable", "reason"}
    assert j["first"].startswith("2026-")


def test_allow_matches():
    assert denied.allow_matches("a.github.com", [".github.com"])
    assert denied.allow_matches("github.com", [".github.com"])
    assert not denied.allow_matches("evilgithub.com", [".github.com"])
    assert not denied.allow_matches("a.example.com", ["example.com"])


UA_DOC = "agentbox-doctor/0123abcd"
NEW = [
    # agentbox logformat: native fields + "<url-encoded User-Agent>"
    "100.500 3 10.213.1.10 TCP_DENIED/403 3348 CONNECT example.org:443 - HIER_NONE/- "
    'text/html "agentbox-doctor%2F0123abcd"',
    "101.000 3 10.213.1.10 TCP_DENIED/403 3348 CONNECT www.wikipedia.org:443 - HIER_NONE/- "
    'text/html "curl%2F8.5.0"',
    # agent forges spaces, quotes, and the field layout inside its UA: encoded
    "101.200 3 10.213.1.10 TCP_DENIED/403 3348 CONNECT evil.example.net:443 - HIER_NONE/- "
    'text/html "x%22%20agentbox-doctor%2F0123abcd%20%22"',
    "101.300 3 10.213.1.10 TCP_DENIED/403 3348 CONNECT noua.example.net:443 - HIER_NONE/- "
    'text/html "-"',
]


def test_new_format_ua():
    f = NEW[0].split()
    assert len(f) == 11 and denied.user_agent(f) == UA_DOC
    assert denied.user_agent(NEW[2].split()) == 'x" agentbox-doctor/0123abcd "'
    assert denied.user_agent(LOG[0].split()) is None  # old native format


def test_doctor_runs_excluded_by_ua_and_window():
    win = [(100.0, 102.0, UA_DOC)]
    hosts = set(by_host(denied.parse(NEW, AGENT, ALLOW, exclude=win)))
    # only the doctor's own request is dropped; real traffic inside the window stays
    assert hosts == {"www.wikipedia.org", "evil.example.net", "noua.example.net"}
    # same UA outside the window: kept
    assert "example.org" in by_host(denied.parse(NEW, AGENT, ALLOW, exclude=[(0, 1, UA_DOC)]))
    # another run's nonce: kept
    other = [(100.0, 102.0, "agentbox-doctor/ffff")]
    assert "example.org" in by_host(denied.parse(NEW, AGENT, ALLOW, exclude=other))
    # old-format lines are never dropped by a window
    first, last = float(LOG[0].split()[0]), float(LOG[-1].split()[0])
    kept = denied.parse(LOG, AGENT, ALLOW, exclude=[(first, last, "agentbox-doctor")])
    assert kept == denied.parse(LOG, AGENT, ALLOW)
