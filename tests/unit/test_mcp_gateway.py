"""Gateway policy (images/mcp-gateway/gateway.py), in-process with FastMCP's
test client and stub upstream FastMCP servers.

Needs the gateway's pinned dependencies; the default CLI test run (stdlib
only) skips this file. Run it with the image lock:

  uv run --no-project --python 3.13 \
    --with-requirements images/mcp-gateway/requirements.lock --with pytest \
    pytest tests/unit/test_mcp_gateway.py
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

import pytest

fastmcp = pytest.importorskip("fastmcp")
from fastmcp import Client, FastMCP  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "images" / "mcp-gateway"))
import gateway as gw  # noqa: E402


def upstream(name: str = "up") -> FastMCP:
    m = FastMCP(name)

    @m.tool
    def allowed_a(x: int) -> str:
        return f"A{x + 1}"

    @m.tool
    def allowed_b(text: str) -> str:
        return f"B:{text}"

    @m.tool
    def forbidden() -> str:
        return "FORBIDDEN-RAN"

    @m.resource("stub://r")
    def res() -> str:
        return "R"

    @m.prompt
    def pr() -> str:
        return "P"

    return m


def cfg(servers: dict) -> dict:
    return gw.load_config({"servers": servers})


def build(servers: dict, log_path, targets):
    return gw.build(cfg(servers), "tok", {}, gw.CallLog(log_path), targets=targets)


def run(coro):
    return asyncio.run(coro)


SERVERS = {
    "s1": {"url": "http://x/mcp", "tools": ["allowed_a", "allowed_b"]},
    "s2": {"url": "http://y/sse", "tools": ["allowed_a"]},
    "all": {"command": ["python3", "x.py"]},
}


@pytest.fixture
def srv(tmp_path):
    log = tmp_path / "calls.jsonl"
    s = build(SERVERS, log, {"s1": upstream(), "s2": upstream(), "all": upstream()})
    return s, log


def test_list_only_allowlisted_namespaced(srv):
    s, _ = srv

    async def go():
        async with Client(s) as c:
            return sorted(t.name for t in await c.list_tools())

    assert run(go()) == [
        "all_allowed_a", "all_allowed_b", "all_forbidden",  # tools omitted: all tools
        "s1_allowed_a", "s1_allowed_b", "s2_allowed_a",
    ]  # fmt: skip


def test_allowed_call_and_rejections(srv):
    s, log = srv

    async def go():
        out = {}
        async with Client(s) as c:
            out["ok"] = (await c.call_tool("s1_allowed_a", {"x": 41})).data
            for n in ("s1_forbidden", "s2_allowed_b", "forbidden", "nosuch_tool", "s3_allowed_a"):
                try:
                    await c.call_tool(n, {"secret_arg": "ARGMARK"})
                    out[n] = "ran"
                except Exception as e:  # noqa: BLE001
                    out[n] = str(e)
        return out

    out = run(go())
    assert out.pop("ok") == "A42"
    assert all("not allowed by the agentbox profile" in v for v in out.values()), out
    lines = [json.loads(x) for x in log.read_text().splitlines()]
    assert {tuple(sorted(x)) for x in lines} == {
        ("args_sha256", "duration_ms", "server", "status", "time", "tool")
    }
    assert lines[0]["server"] == "s1" and lines[0]["tool"] == "allowed_a"
    assert lines[0]["status"] == "ok"
    assert lines[0]["args_sha256"] == gw.args_sha256({"x": 41})
    assert [x["status"] for x in lines[1:]] == ["denied"] * 5
    assert "ARGMARK" not in log.read_text() and "A42" not in log.read_text()


def test_resources_and_prompts_not_exposed(srv):
    s, _ = srv

    async def go():
        async with Client(s) as c:
            r = (
                await c.list_resources(),
                await c.list_prompts(),
                await c.list_resource_templates(),
            )
            errs = []
            for f in (lambda: c.read_resource("stub://s1/r"), lambda: c.get_prompt("s1_pr")):
                try:
                    await f()
                    errs.append("ran")
                except Exception as e:  # noqa: BLE001
                    errs.append(type(e).__name__)
            return r, errs

    lists, errs = run(go())
    assert lists == ([], [], [])
    assert "ran" not in errs


def test_visibility_layer_alone_blocks(tmp_path, monkeypatch):
    """Layer 1 (FastMCP enable(only=True) on each proxy) holds even if the
    middleware policy allowed everything."""
    monkeypatch.setattr(gw.Policy, "resolve", lambda self, n: ("s1", n[3:], True))
    s = build({"s1": SERVERS["s1"]}, tmp_path / "l", {"s1": upstream()})

    async def go():
        async with Client(s) as c:
            names = sorted(t.name for t in await c.list_tools())
            try:
                r = await c.call_tool("s1_forbidden", {})
                return names, r.data
            except Exception as e:  # noqa: BLE001
                return names, f"rejected: {e}"

    names, res = run(go())
    assert names == ["s1_allowed_a", "s1_allowed_b"]
    assert res.startswith("rejected") and "FORBIDDEN-RAN" not in res


def test_zero_servers(tmp_path):
    s = build({}, tmp_path / "l", {})

    async def go():
        async with Client(s) as c:
            return await c.list_tools()

    assert run(go()) == []


def test_http_auth_401_and_200(tmp_path):
    """The HTTP app requires the bearer (StaticTokenVerifier)."""
    httpx = pytest.importorskip("httpx2")
    s = build({}, tmp_path / "l", {})
    app = s.http_app(path="/mcp")
    body = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                       "clientInfo": {"name": "t", "version": "1"}}}  # fmt: skip
    hdr = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}

    async def go():
        codes = []
        async with app.router.lifespan_context(app):
            t = httpx.ASGITransport(app=app)
            async with httpx.AsyncClient(transport=t, base_url="http://mcp-gateway:8080") as c:
                for auth in (None, "Bearer wrong", "Bearer tok"):
                    h = dict(hdr, **({"Authorization": auth} if auth else {}))
                    codes.append((await c.post("/mcp", json=body, headers=h)).status_code)
        return codes

    assert run(go()) == [401, 401, 200]


def test_no_incoming_header_forwarding(monkeypatch):
    """Proxies force forward_incoming_headers=True; the gateway transport
    turns it off so the agent's Authorization never reaches an upstream."""
    from fastmcp.client.transports import SSETransport, StreamableHttpTransport
    from fastmcp.client.transports.base import TransportOptions

    seen = []
    for base in (StreamableHttpTransport, SSETransport):

        def fake(self, *, transport_options=None, **kw):
            seen.append(transport_options.forward_incoming_headers)
            return "cm"

        monkeypatch.setattr(base, "connect_session", fake)
    for url in ("http://h/mcp", "http://h/sse"):
        t = gw.upstream_transport({"url": url, "command": None, "bearer_env": None}, {})
        assert t.connect_session(transport_options=TransportOptions(
            forward_incoming_headers=True)) == "cm"  # fmt: skip
    assert seen == [False, False]


def test_transport_choice_and_bearer():
    from fastmcp.client.transports import SSETransport, StreamableHttpTransport

    t = gw.upstream_transport({"url": "https://a/mcp", "command": None, "bearer_env": "B"},
                              {"B": "v"})  # fmt: skip
    assert isinstance(t, StreamableHttpTransport) and t.auth is not None
    t = gw.upstream_transport({"url": "http://a/sse/", "command": None, "bearer_env": None}, {})
    assert isinstance(t, SSETransport) and t.auth is None
    with pytest.raises(gw.ConfigError, match="not delivered"):
        gw.upstream_transport({"url": "https://a/mcp", "command": None, "bearer_env": "B"}, {})


def test_stdio_env_has_no_secrets(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "STDIO_HOME", str(tmp_path / "h"))
    env = {"PATH": "/p", "MCP_GATEWAY_TOKEN": "t", "DOCS_TOK": "d", "HTTPS_PROXY": "x"}
    t = gw.upstream_transport({"url": None, "command": ["uvx", "srv"], "bearer_env": None}, env)
    assert t.command == "uvx" and t.args == ["srv"]
    assert t.env == {"PATH": "/p", "HTTPS_PROXY": "x", "HOME": str(tmp_path / "h")}


def test_take_env_removes_secrets():
    env = {"MCP_GATEWAY_TOKEN": "t", "B": "b", "PATH": "/p"}
    assert gw.take_env(env, ["MCP_GATEWAY_TOKEN", "B", "MISSING"]) == {
        "MCP_GATEWAY_TOKEN": "t", "B": "b"}  # fmt: skip
    assert env == {"PATH": "/p"}


@pytest.mark.parametrize(
    "bad",
    [
        {"x": 1},
        {"servers": {"a b": {"url": "https://a"}}},
        {"servers": {"a": {}}},
        {"servers": {"a": {"url": "https://a", "command": ["x"]}}},
        {"servers": {"a": {"url": "ftp://a"}}},
        {"servers": {"a": {"command": []}}},
        {"servers": {"a": {"command": ["x"], "bearer_env": "B"}}},
        {"servers": {"a": {"url": "https://a", "bearer_env": "1B"}}},
        {"servers": {"a": {"url": "https://a", "tools": []}}},
        {"servers": {"a": {"url": "https://a", "tools": ["x y"]}}},
        {"servers": {"a": {"url": "https://a", "extra": 1}}},
        {"servers": {"a": {"url": "https://a"}, "a_b": {"url": "https://b"}}},
    ],
)
def test_config_rejects(bad):
    with pytest.raises(gw.ConfigError):
        gw.load_config(bad)


def test_empty_token_refused(tmp_path):
    with pytest.raises(gw.ConfigError):
        gw.build({}, "", {}, gw.CallLog(tmp_path / "l"))


STDIO_OK = (
    "from fastmcp import FastMCP\n"
    "m = FastMCP('s')\n"
    "@m.tool\n"
    "def t1() -> str:\n"
    "    return 'x'\n"
    "m.run(show_banner=False)\n"
)


def test_probe_status(tmp_path, monkeypatch):
    monkeypatch.setattr(gw, "STDIO_HOME", str(tmp_path / "h"))
    servers = cfg({
        "good": {"command": [sys.executable, "-c", STDIO_OK], "tools": ["t1", "t2"]},
        "bad": {"command": ["/nonexistent/agentbox-srv"]},
        "slow": {"command": [sys.executable, "-c", "import time; time.sleep(30)"]},
        "http": {"url": "http://127.0.0.1:9/mcp", "bearer_env": "B"},
    })  # fmt: skip
    env = {"PATH": "/usr/bin:/bin", "B": "SECRET-BEARER-VALUE"}
    st = run(gw.probe(servers, env, timeout=8))
    s = st["servers"]
    assert s["good"] == {"state": "connected", "tools": 1, "missing_allowed": ["t2"]}
    for n in ("bad", "slow", "http"):
        assert s[n]["state"] == "failed" and s[n]["reason"], s[n]
    assert "SECRET-BEARER-VALUE" not in json.dumps(st)
    gw.write_status(tmp_path / "status.json", st)
    assert json.loads((tmp_path / "status.json").read_text()) == st


def test_short_reason_scrubs():
    e = RuntimeError("bad token SECRET in url")
    assert gw.short_reason(e, ["SECRET"]) == "RuntimeError: bad token <redacted> in url"


def test_short_reason_innermost_cause():
    try:
        try:
            raise ConnectionRefusedError("refused :9")
        except OSError as inner:
            raise ExceptionGroup("tg", [RuntimeError("wrap")]) from inner
    except ExceptionGroup as e:
        r = gw.short_reason(e, [])
    assert "ConnectionRefusedError: refused :9" in r


def test_short_reason_strips_controls():
    e = RuntimeError("upstream says \x1b]0;PWNED\x07\x1b[2J\x1b[31mFAKE\x1b[0m \x9b")
    r = gw.short_reason(e, [])
    assert not any(c in r for c in "\x1b\x07\x9b") and "PWNED" in r and "\\x1b" in r


def test_call_log_rotates_and_truncates(tmp_path, srv):
    log = gw.CallLog(tmp_path / "c.jsonl", max_bytes=300)
    for _ in range(10):
        log.write(server="s", tool="t", status="ok")
    assert (tmp_path / "c.jsonl.1").is_file()
    assert (tmp_path / "c.jsonl").stat().st_size < 300 + 200
    s, logf = srv

    async def go():
        async with Client(s) as c:
            with pytest.raises(Exception):  # noqa: B017
                await c.call_tool("x" * 5000, {})

    run(go())
    rec = json.loads(logf.read_text().splitlines()[-1])
    assert len(rec["tool"]) == gw.NAME_MAX and rec["status"] == "denied"
