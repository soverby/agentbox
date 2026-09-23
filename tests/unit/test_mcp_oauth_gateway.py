"""OAuth upstreams in the gateway (images/mcp-gateway/upstream_oauth.py,
gateway.py wiring), PLAN §2.6 P6b.

TokenStore tests are stdlib only. The `httpx2` tests (the Auth flow against
an in-process TLS stub AS + resource) need the gateway lock:

  uv run --no-project --python 3.13 \
    --with-requirements images/mcp-gateway/requirements.lock --with pytest \
    pytest tests/unit/test_mcp_oauth_gateway.py
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "images" / "mcp-gateway"))
import upstream_oauth as uo  # noqa: E402

TE = "https://as.example/token"


def tset(**kw) -> dict:
    ts = {"v": 1, "login_id": "L1", "client_id": "cid", "token_endpoint": TE,
          "revocation_endpoint": "https://as.example/revoke", "resource": "https://m.example/mcp",
          "auth_method": "none", "access_token": "AT0", "expires_at": 10_000,
          "refresh_token": "RT0", "obtained_at": "2026-09-23T00:00:00+00:00"}  # fmt: skip
    ts.update(kw)
    return ts


class AS:
    """Fake token endpoint: rotates refresh tokens, can refuse."""

    def __init__(self):
        self.n = 0
        self.valid_rt = {"RT0"}
        self.calls: list[dict] = []
        self.status = None

    def post(self, url, form, headers):
        assert url.startswith("https://")
        self.calls.append(dict(form, _url=url, _auth=headers.get("Authorization")))
        if self.status is not None:
            return self.status, b'{"error":"temporarily_unavailable"}'
        if form.get("grant_type") != "refresh_token" or form["refresh_token"] not in self.valid_rt:
            return 400, b'{"error":"invalid_grant","error_description":"RT0 \\u001b[2J bad"}'
        self.valid_rt.discard(form["refresh_token"])
        self.n += 1
        new = f"RT{self.n}"
        self.valid_rt.add(new)
        doc = {"access_token": f"AT{self.n}", "token_type": "Bearer", "expires_in": 600,
               "refresh_token": new}  # fmt: skip
        return 200, json.dumps(doc).encode()


class Clock:
    def __init__(self, t=1000.0):
        self.t = t

    def __call__(self):
        return self.t


def store(tmp_path, ts=None, as_=None, clock=None, **kw):
    return uo.TokenStore("lin", json.dumps(ts or tset()), "agentbox mcp login p lin", tmp_path,
                         post=(as_ or AS()).post, now=clock or Clock(), **kw)  # fmt: skip


def test_parse_token_set_validation():
    uo.parse_token_set(json.dumps(tset()))
    for bad, msg in (
        (tset(v=2), "format"),
        (tset(token_endpoint="http://as.example/token"), "https"),
        (tset(token_endpoint="https://u@as.example/t"), "plain"),
        (tset(client_id=""), "client_id"),
        (tset(access_token=None, refresh_token=None), "neither"),
        (tset(auth_method="private_key_jwt"), "auth_method"),
    ):
        with pytest.raises(uo.TokenSetError, match=msg):
            uo.parse_token_set(json.dumps(bad))


def test_valid_token_no_refresh(tmp_path):
    a = AS()
    s = store(tmp_path, as_=a)
    assert s.get_access() == "AT0" and a.calls == []
    vol = tmp_path / "lin.json"
    assert vol.is_file() and oct(vol.stat().st_mode & 0o777) == "0o600"


def test_expiry_refreshes_and_rotation_persists(tmp_path):
    a, c = AS(), Clock(10_000 - 30)  # inside the 60 s skew
    s = store(tmp_path, as_=a, clock=c)
    assert s.get_access() == "AT1"
    call = a.calls[0]
    assert call["grant_type"] == "refresh_token" and call["refresh_token"] == "RT0"
    assert call["resource"] == "https://m.example/mcp" and call["client_id"] == "cid"
    vol = json.loads((tmp_path / "lin.json").read_text())
    assert vol["refresh_token"] == "RT1" and vol["expires_at"] == int(c.t + 600)
    assert vol["refreshes"] == 1 and vol["last_refresh"]
    # a new process (gateway restart, probe exec) with the old delivered set
    # uses the rotated volume copy, not the spent RT0
    c.t += 700
    s2 = store(tmp_path, as_=a, clock=c)
    assert s2.get_access() == "AT2" and a.calls[-1]["refresh_token"] == "RT1"


def test_401_refresh_once_and_other_process_already_refreshed(tmp_path):
    a = AS()
    s1, s2 = store(tmp_path, as_=a), store(tmp_path, as_=a)
    assert s1.refresh("AT0") == "AT1"
    # s2 saw a 401 with the same stale token: it takes s1's result, no 2nd grant
    assert s2.refresh("AT0") == "AT1" and len(a.calls) == 1


def test_concurrent_refresh_threads_single_grant(tmp_path):
    a = AS()
    s = store(tmp_path, as_=a)
    out = []
    ts = [threading.Thread(target=lambda: out.append(s.refresh("AT0"))) for _ in range(8)]
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    assert out == ["AT1"] * 8 and len(a.calls) == 1


def test_refused_refresh_marks_relogin(tmp_path):
    a = AS()
    a.valid_rt = set()  # the AS revoked the refresh token
    failed = []
    s = store(tmp_path, as_=a, on_failed=lambda n, r: failed.append((n, r)))
    with pytest.raises(uo.ReloginNeeded, match="agentbox mcp login p lin"):
        s.refresh("AT0")
    assert failed == [("lin", "re-login needed (agentbox mcp login p lin)")]
    st = s.status()
    assert (
        st["state"] == "needs_login" and st["reason"] == "refresh refused: HTTP 400 invalid_grant"
    )
    blob = json.dumps(st) + (tmp_path / "lin.json").read_text()
    assert "\x1b" not in blob and "AT0" not in json.dumps(st)
    # no retry storm: later calls fail fast without a token request
    with pytest.raises(uo.ReloginNeeded):
        s.get_access()
    assert len(a.calls) == 1
    # a new login (new login_id) replaces the failed volume copy
    s3 = store(tmp_path, ts=tset(login_id="L2", access_token="NEW", refresh_token="RTX"), as_=a)
    assert s3.get_access() == "NEW" and s3.status()["state"] == "ok"


def test_transient_error_not_marked(tmp_path):
    a = AS()
    a.status = 503
    s = store(tmp_path, as_=a, clock=Clock(20_000))
    with pytest.raises(uo.RefreshError, match="HTTP 503"):
        s.get_access()
    assert s.status()["state"] == "ok"  # refresh token still there: retried later

    def boom(url, form, headers):
        raise OSError(f"connect failed {form['refresh_token']}")

    s2 = uo.TokenStore("x", json.dumps(tset()), "h", tmp_path, post=boom, now=Clock(20_000))
    with pytest.raises(uo.RefreshError) as ei:
        s2.get_access()
    assert "RT0" not in str(ei.value)  # exception text is never copied


def test_minimal_set_fetches_access_at_start(tmp_path):
    a = AS()
    s = store(tmp_path, ts=tset(access_token=None, expires_at=None), as_=a)
    assert s.get_access() == "AT1" and len(a.calls) == 1


def test_client_secret_basic_and_post(tmp_path):
    a = AS()
    s = store(tmp_path, ts=tset(auth_method="client_secret_basic", client_secret="S"), as_=a,
              clock=Clock(20_000))  # fmt: skip
    s.get_access()
    assert a.calls[0]["_auth"].startswith("Basic ") and "client_id" not in a.calls[0]
    a2 = AS()
    s = uo.TokenStore("p", json.dumps(tset(auth_method="client_secret_post", client_secret="S")),
                      "h", tmp_path, post=a2.post, now=Clock(20_000))  # fmt: skip
    s.get_access()
    assert a2.calls[0]["client_secret"] == "S" and a2.calls[0]["_auth"] is None


def test_status_names_and_times_only(tmp_path):
    s = store(tmp_path, clock=Clock(9_000))
    st = s.status()
    assert st["state"] == "ok" and st["expires_in"] == 1000 and st["has_refresh_token"]
    assert not any(v in json.dumps(st) for v in ("AT0", "RT0", "cid"))


def test_logout_revokes_newest_and_removes(tmp_path):
    a = AS()
    s = store(tmp_path, as_=a)
    s.refresh("AT0")  # rotate: newest is RT1 / AT1
    result, cur = s.logout()
    rv = [c for c in a.calls if c["_url"] == "https://as.example/revoke"]
    assert [(c["token"], c["token_type_hint"]) for c in rv] == [
        ("RT1", "refresh_token"), ("AT1", "access_token")]  # fmt: skip
    assert cur["refresh_token"] == "RT1" and result.startswith("failed")  # fake AS: 400
    assert not (tmp_path / "lin.json").exists() and not (tmp_path / "lin.lock").exists()
    assert uo.remove_volume_copy("lin", tmp_path) is None


def test_logout_basic_auth_no_secret_in_form(tmp_path):
    a = AS()
    s = store(tmp_path, ts=tset(auth_method="client_secret_basic", client_secret="S"), as_=a)
    s.logout()
    for c in a.calls:
        assert "client_secret" not in c and "client_id" not in c and c["_auth"].startswith("Basic ")


def test_remove_volume_copy_returns_set(tmp_path):
    (tmp_path / "lin.json").write_text(json.dumps(tset(refresh_token="RT9")))
    assert uo.remove_volume_copy("lin", tmp_path)["refresh_token"] == "RT9"
    assert not (tmp_path / "lin.json").exists()


# ---------------------------------------------------------------- gateway.py wiring


@pytest.fixture
def gw():
    pytest.importorskip("fastmcp")
    import gateway

    return gateway


def test_config_oauth_env(gw):
    cfg = {"profile": "p", "servers": {"lin": {"url": "https://m.example/mcp",
                                                "oauth_env": "_MCP_OAUTH_LIN"}}}  # fmt: skip
    out = gw.load_config(cfg)
    assert out["lin"]["oauth_env"] == "_MCP_OAUTH_LIN"
    for bad in ({"url": "http://m.example/mcp", "oauth_env": "_MCP_OAUTH_LIN"},
                {"url": "https://m.example/mcp", "oauth_env": "A", "bearer_env": "B"},
                {"url": "https://m.example/mcp", "oauth_env": "bad-name"}):  # fmt: skip
        with pytest.raises(gw.ConfigError):
            gw.load_config({"servers": {"lin": bad}})
    with pytest.raises(gw.ConfigError):
        gw.load_config({"profile": "../x", "servers": {}})


def test_make_stores_and_probe_reasons(gw, tmp_path):
    import asyncio

    servers = gw.load_config({"profile": "p", "servers": {
        "a": {"url": "https://a.example/mcp", "oauth_env": "_MCP_OAUTH_A"},
        "b": {"url": "https://b.example/mcp", "oauth_env": "_MCP_OAUTH_B"},
        "c": {"url": "https://c.example/mcp", "oauth_env": "_MCP_OAUTH_C"}}})  # fmt: skip
    env = {"_MCP_OAUTH_A": json.dumps(tset()), "_MCP_OAUTH_C": "{not json"}
    stores, problems = gw.make_stores(servers, env, "p", str(tmp_path))
    assert set(stores) == {"a"}
    assert problems["b"] == "not logged in (agentbox mcp login p b)"
    assert "re-login needed (agentbox mcp login p c)" in problems["c"]
    a = AS()
    a.valid_rt = set()
    stores["a"].post = a.post
    stores["a"].now = Clock(20_000)  # expired: refresh -> refused
    st = asyncio.run(gw.probe(servers, env, 10, stores, problems))["servers"]
    assert st["a"] == {"state": "failed", "reason": "re-login needed (agentbox mcp login p a)"}
    assert st["b"]["state"] == "failed" and st["c"]["state"] == "failed"
    # not-logged-in servers are not mounted; logged-in ones are
    main = gw.build(servers, "tok", env, gw.CallLog(None), stores=stores)
    assert main is not None
    assert "_MCP_OAUTH_A" in gw.secret_names(servers)


def test_status_patcher(gw, tmp_path):
    f = tmp_path / "status.json"
    f.write_text(json.dumps({"servers": {"x": {"state": "connected"}}}))
    gw.status_patcher(str(f))("lin", "re-login needed (agentbox mcp login p lin)")
    st = json.loads(f.read_text())["servers"]
    assert st["x"]["state"] == "connected" and st["lin"]["state"] == "failed"


# ---------------------------------------------------------------- httpx2 Auth, real TLS


@pytest.fixture(scope="module")
def tls(tmp_path_factory):
    if shutil.which("openssl") is None:
        pytest.skip("openssl not found")
    d = tmp_path_factory.mktemp("tls")
    run = lambda *a: subprocess.run(["openssl", *a], check=True, capture_output=True)  # noqa: E731
    run("req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=t-ca",
        "-keyout", str(d / "ca.key"), "-out", str(d / "ca.pem"),
        "-addext", "basicConstraints=critical,CA:TRUE",
        "-addext", "keyUsage=critical,keyCertSign,cRLSign")  # fmt: skip
    run("req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
        "-keyout", str(d / "s.key"), "-out", str(d / "s.csr"))  # fmt: skip
    (d / "ext").write_text("subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\n"
                           "extendedKeyUsage=serverAuth\n")  # fmt: skip
    run("x509", "-req", "-in", str(d / "s.csr"), "-CA", str(d / "ca.pem"), "-CAkey",
        str(d / "ca.key"), "-CAcreateserial", "-days", "1", "-extfile", str(d / "ext"),
        "-out", str(d / "s.pem"))  # fmt: skip
    return d


def serve_stub(d: Path):
    """TLS stub: /token (refresh grant, rotating) and /res (401 unless the
    current access token). Records what it saw."""
    import http.server
    import ssl
    from urllib.parse import parse_qs

    state = {"access": "AT0", "rt": "RT0", "n": 0, "seen": [], "grants": []}

    class H(http.server.BaseHTTPRequestHandler):
        def _send(self, code, doc):
            b = json.dumps(doc).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(b)))
            self.end_headers()
            self.wfile.write(b)

        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            body = self.rfile.read(n)
            if self.path == "/token":
                f = {k: v[0] for k, v in parse_qs(body.decode()).items()}
                state["grants"].append(f)
                if f.get("refresh_token") != state["rt"]:
                    return self._send(400, {"error": "invalid_grant"})
                state["n"] += 1
                state["access"], state["rt"] = f"AT{state['n']}", f"RT{state['n']}"
                return self._send(
                    200,
                    {
                        "access_token": state["access"],
                        "token_type": "Bearer",
                        "expires_in": 3600,
                        "refresh_token": state["rt"],
                    },
                )
            state["seen"].append((self.headers.get("Authorization"), body))
            if self.headers.get("Authorization") != f"Bearer {state['access']}":
                return self._send(401, {"error": "invalid_token"})
            return self._send(200, {"ok": True, "echo": body.decode()})

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(d / "s.pem", d / "s.key")
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, state


def test_httpx_auth_refreshes_on_401(gw, tls, tmp_path, monkeypatch):
    import asyncio

    import httpx2

    monkeypatch.setenv("SSL_CERT_FILE", str(tls / "ca.pem"))
    for k in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY"):
        monkeypatch.delenv(k, raising=False)
    srv, state = serve_stub(tls)
    port = srv.server_address[1]
    try:
        ts = tset(token_endpoint=f"https://localhost:{port}/token", expires_at=10**10)
        s = uo.TokenStore("lin", json.dumps(ts), "h", tmp_path)  # real httpx_post
        state["access"] = "AT-server-rotated"  # the server no longer accepts AT0

        async def call():
            async with httpx2.AsyncClient(auth=uo.make_auth(s)) as c:
                return await c.post(f"https://localhost:{port}/res", content=b'{"x":1}')

        r = asyncio.run(call())
        assert r.status_code == 200 and r.json()["echo"] == '{"x":1}'  # body re-sent
        assert [a for a, _ in state["seen"]] == ["Bearer AT0", "Bearer AT1"]
        assert state["grants"][0]["grant_type"] == "refresh_token"
        assert json.loads((tmp_path / "lin.json").read_text())["refresh_token"] == "RT1"
        # the AS revokes the refresh token and the access token: re-login needed
        state["rt"], state["access"] = "revoked", "revoked"
        with pytest.raises(Exception) as ei:
            asyncio.run(call())
        assert gw.find_exc(ei.value, uo.ReloginNeeded) is not None
        assert s.status()["state"] == "needs_login"
    finally:
        srv.shutdown()
    assert os.environ.get("SSL_CERT_FILE") == str(tls / "ca.pem")
