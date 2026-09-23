"""OAuth for MCP upstreams, host side (cli/agentbox/mcpoauth.py, mcpcmd.py),
plus the profile, delivery, and render parts (PLAN §2.6, P6b). Stdlib only."""

from __future__ import annotations

import json
import threading
import urllib.request

import pytest
from agentbox import compose, delivery, mcpgw, mcpoauth, network, paths
from agentbox.mcpoauth import OAuthError, Response
from agentbox.profile import ProfileError, parse_profile

SRV = "https://mcp.example.com/mcp"
AS = "https://auth.example.com/tenant"
PRM_URL = "https://mcp.example.com/.well-known/oauth-protected-resource/mcp"
ASM_URL = "https://auth.example.com/.well-known/oauth-authorization-server/tenant"
AS_META = {
    "issuer": AS,
    "authorization_endpoint": f"{AS}/authorize",
    "token_endpoint": f"{AS}/token",
    "registration_endpoint": f"{AS}/register",
    "revocation_endpoint": f"{AS}/revoke",
    "code_challenge_methods_supported": ["S256"],
    "scopes_supported": ["read", "offline_access"],
}


def js(status: int, doc, headers=None) -> Response:
    return Response(status, {k.lower(): v for k, v in (headers or {}).items()},
                    json.dumps(doc).encode())  # fmt: skip


class FakeHttp(mcpoauth.Http):
    """Routes (method, url) to canned responses; records requests."""

    def __init__(self, routes: dict):
        super().__init__()
        self.routes = routes
        self.seen: list[tuple[str, str, bytes | None, dict]] = []

    def request(self, method, url, body=None, headers=None):
        mcpoauth.https_url(url, "request")
        self.seen.append((method, url, body, headers or {}))
        r = self.routes.get((method, url))
        if callable(r):
            r = r(body, headers or {})
        return r if r is not None else js(404, {"error": "not_found"})


def base_routes(www=None):
    www = www if www is not None else (
        f'Bearer resource_metadata="{PRM_URL}", scope="read"')  # fmt: skip
    return {
        ("POST", SRV): js(401, {}, {"WWW-Authenticate": www} if www else {}),
        ("GET", PRM_URL): js(
            200,
            {"resource": SRV, "authorization_servers": [AS], "scopes_supported": ["read", "write"]},
        ),  # fmt: skip
        ("GET", ASM_URL): js(200, AS_META),
    }


# ---------------------------------------------------------------- parsing


def test_www_authenticate_bearer_params():
    h = ('Basic realm="x", Bearer error="invalid_token", '
         'resource_metadata="https://a.example/.well-known/oauth-protected-resource", '
         'scope="files:read files:write", error_description="say \\"hi\\""')  # fmt: skip
    p = mcpoauth.parse_www_authenticate(h)
    assert p["resource_metadata"] == "https://a.example/.well-known/oauth-protected-resource"
    assert p["scope"] == "files:read files:write"
    assert p["error"] == "invalid_token" and p["error_description"] == 'say "hi"'
    assert "realm" not in p  # Basic's parameters are not the Bearer's
    assert mcpoauth.parse_www_authenticate('Bearer realm="r"') == {"realm": "r"}
    assert mcpoauth.parse_www_authenticate("") == {}


def test_well_known_orders():
    assert mcpoauth.well_known_prm(SRV) == [
        PRM_URL, "https://mcp.example.com/.well-known/oauth-protected-resource"]  # fmt: skip
    assert mcpoauth.well_known_prm("https://m.example") == [
        "https://m.example/.well-known/oauth-protected-resource"]  # fmt: skip
    assert mcpoauth.well_known_as(AS) == [
        ASM_URL,
        "https://auth.example.com/.well-known/openid-configuration/tenant",
        "https://auth.example.com/tenant/.well-known/openid-configuration",
    ]
    assert mcpoauth.well_known_as("https://a.example") == [
        "https://a.example/.well-known/oauth-authorization-server",
        "https://a.example/.well-known/openid-configuration",
    ]


def test_pkce_rfc7636_vector():
    # RFC 7636 Appendix B
    v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert mcpoauth.pkce_challenge(v) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    v2, c2 = mcpoauth.pkce_pair()
    assert 43 <= len(v2) <= 128 and c2 == mcpoauth.pkce_challenge(v2) and "=" not in c2


@pytest.mark.parametrize("u", [
    "http://a.example/x", "https://user@a.example/", "https://a.example/#f", "ftp://a",
    "https://a.example/\x1b[2J", "https://a.example:99999/", "javascript:alert(1)", 42,
])  # fmt: skip
def test_https_url_refuses(u):
    with pytest.raises(OAuthError):
        mcpoauth.https_url(u, "x")


# ---------------------------------------------------------------- discovery


def test_discover_from_401_header():
    h = FakeHttp(base_routes())
    d = mcpoauth.discover(h, SRV)
    assert d.resource == SRV and d.issuer == AS and d.as_meta == AS_META
    assert d.challenge_scope == ["read"] and d.prm_scopes == ["read", "write"]
    assert [x[1] for x in h.seen] == [SRV, PRM_URL, ASM_URL]
    # 401 challenge scope wins; offline_access added because the AS lists it
    assert mcpoauth.choose_scopes(d, None) == ["read", "offline_access"]
    assert mcpoauth.choose_scopes(d, ["write"]) == ["write", "offline_access"]


def test_discover_well_known_fallback_root():
    r = base_routes(www="")
    root = "https://mcp.example.com/.well-known/oauth-protected-resource"
    r[("GET", root)] = r.pop(("GET", PRM_URL))
    h = FakeHttp(r)
    d = mcpoauth.discover(h, SRV)
    assert [x[1] for x in h.seen] == [SRV, PRM_URL, root, ASM_URL]
    assert d.challenge_scope is None and mcpoauth.choose_scopes(d, None) == [
        "read", "write", "offline_access"]  # fmt: skip


def test_discover_oidc_fallback_and_root_resource():
    r = base_routes()
    r[("GET", PRM_URL)] = js(200, {"resource": "https://MCP.example.com/",
                                   "authorization_servers": [AS]})  # fmt: skip
    oidc = "https://auth.example.com/.well-known/openid-configuration/tenant"
    r[("GET", oidc)] = r.pop(("GET", ASM_URL))
    d = mcpoauth.discover(FakeHttp(r), SRV)
    assert d.resource == "https://mcp.example.com"  # root resource, canonical form


@pytest.mark.parametrize("mutate, msg", [
    (lambda r: r.__setitem__(("POST", SRV), js(200, {})), "not 401"),
    (lambda r: r.__setitem__(("GET", PRM_URL), js(200, {"resource": "https://evil.example/mcp",
                                                        "authorization_servers": [AS]})),
     "not this server"),
    (lambda r: r.__setitem__(("GET", PRM_URL), js(200, {"resource": "https://mcp.example.com/other",
                                                        "authorization_servers": [AS]})),
     "not this server"),
    (lambda r: r.__setitem__(("GET", PRM_URL), js(200, {"resource": SRV,
                                                        "authorization_servers": ["http://a.x"]})),
     "not https"),
    (lambda r: r.__setitem__(("GET", ASM_URL), js(200, {**AS_META,
                                                        "issuer": "https://honest.example"})),
     "RFC 8414"),
    (lambda r: r.__setitem__(("POST", SRV), js(401, {}, {
        "WWW-Authenticate": 'Bearer resource_metadata="http://mcp.example.com/prm"'})),
     "not https"),
    (lambda r: r.pop(("GET", PRM_URL)), "no protected resource metadata"),
])  # fmt: skip
def test_discover_refuses(mutate, msg):
    r = base_routes()
    mutate(r)
    with pytest.raises(OAuthError, match=msg):
        mcpoauth.discover(FakeHttp(r), SRV)


def test_validate_as_pkce_and_registration():
    mcpoauth.validate_as(AS_META, need_registration=True)
    for bad in ({"code_challenge_methods_supported": ["plain"]},
                {"code_challenge_methods_supported": None}):  # fmt: skip
        with pytest.raises(OAuthError, match="PKCE S256"):
            mcpoauth.validate_as({**AS_META, **bad}, False)
    with pytest.raises(OAuthError, match="client_id"):
        mcpoauth.validate_as({**AS_META, "registration_endpoint": None}, True)
    with pytest.raises(OAuthError, match="not https"):
        mcpoauth.validate_as({**AS_META, "token_endpoint": "http://auth.example.com/t"}, False)


def test_redirects_only_https():
    h = FakeHttp({("GET", "https://a.example/m"): js(302, {}, {"Location": "http://a.example/m2"})})
    with pytest.raises(OAuthError, match="not https"):
        h.get_json("https://a.example/m", "meta")
    h = FakeHttp({
        ("GET", "https://a.example/m"): js(301, {}, {"Location": "/m2"}),
        ("GET", "https://a.example/m2"): js(200, {"ok": 1}),
    })  # fmt: skip
    assert h.get_json("https://a.example/m", "meta") == (200, {"ok": 1})
    loop = FakeHttp({("GET", "https://a.example/m"): js(302, {}, {"Location": "/m"})})
    with pytest.raises(OAuthError, match="too many redirects"):
        loop.get_json("https://a.example/m", "meta")


def test_http_refuses_plain_http_and_caps_body():
    with pytest.raises(OAuthError, match="not https"):
        mcpoauth.Http().request("GET", "http://127.0.0.1:9/")
    assert mcpoauth.MAX_BODY <= 256 * 1024


# ---------------------------------------------------------------- DCR


def test_dcr_request_and_response():
    got = {}

    def reg(body, headers):
        got.update(json.loads(body))
        return js(201, {"client_id": "cid-1", "client_secret": "csec",
                        "token_endpoint_auth_method": "client_secret_post"})  # fmt: skip

    h = FakeHttp({("POST", f"{AS}/register"): reg})
    c = mcpoauth.register(h, AS_META, "http://127.0.0.1:5555/callback", ["read"])
    assert got == {"client_name": "agentbox", "application_type": "native",
                   "redirect_uris": ["http://127.0.0.1:5555/callback"],
                   "grant_types": ["authorization_code", "refresh_token"],
                   "response_types": ["code"], "token_endpoint_auth_method": "none",
                   "scope": "read"}  # fmt: skip
    assert (c.client_id, c.client_secret, c.auth_method) == ("cid-1", "csec", "client_secret_post")
    form: dict = {}
    assert mcpoauth.client_auth(c, form) == {} and form == {"client_id": "cid-1",
                                                           "client_secret": "csec"}  # fmt: skip
    basic = mcpoauth.ClientInfo("a b", "p:w", "client_secret_basic")
    form = {}
    assert mcpoauth.client_auth(basic, form)["Authorization"] == "Basic YSUyMGI6cCUzQXc="
    assert form == {}


@pytest.mark.parametrize("resp, msg", [
    (js(400, {"error": "invalid_redirect_uri", "error_description": "\x1b[2J"}),
     "invalid_redirect_uri"),
    (js(201, {"client_secret": "x"}), "no client_id"),
    (js(201, {"client_id": "c", "token_endpoint_auth_method": "private_key_jwt"}), "unsupported"),
    (js(201, {"client_id": "c", "token_endpoint_auth_method": "client_secret_post"}),
     "without a client_secret"),
])  # fmt: skip
def test_dcr_errors(resp, msg):
    h = FakeHttp({("POST", f"{AS}/register"): resp})
    with pytest.raises(OAuthError, match=msg) as ei:
        mcpoauth.register(h, AS_META, "http://127.0.0.1:1/callback", [])
    assert "\x1b" not in str(ei.value)


# ---------------------------------------------------------------- loopback + iss


def _hit(url: str) -> int:
    try:
        with urllib.request.urlopen(url, timeout=5) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code


def test_loopback_state_mismatch_refused():
    with mcpoauth.LoopbackServer("good-state") as lb:
        assert lb.redirect_uri.startswith("http://127.0.0.1:")
        assert _hit(lb.redirect_uri.replace("/callback", "/other")) == 404
        assert _hit(lb.redirect_uri + "?code=c&state=bad-state") == 400
        with pytest.raises(OAuthError, match="state mismatch"):
            lb.wait(5)


def test_loopback_ok_and_timeout():
    with mcpoauth.LoopbackServer("s1") as lb:
        assert _hit(lb.redirect_uri + "?code=abc&state=s1&iss=x") == 200
        assert lb.wait(5) == {"code": "abc", "state": "s1", "iss": "x"}
    with mcpoauth.LoopbackServer("s2") as lb, pytest.raises(OAuthError, match="within"):
        lb.wait(0.2)


def test_iss_rfc9207():
    m = dict(AS_META)
    mcpoauth.check_iss(m, AS, {})  # not advertised, absent: proceed
    mcpoauth.check_iss(m, AS, {"iss": AS})
    with pytest.raises(OAuthError):
        mcpoauth.check_iss(m, AS, {"iss": AS + "/"})  # no normalisation
    m["authorization_response_iss_parameter_supported"] = True
    with pytest.raises(OAuthError, match="no iss"):
        mcpoauth.check_iss(m, AS, {})


# ---------------------------------------------------------------- full flow (fake AS)


def flow_routes(tokens: dict, seen: dict):
    r = base_routes()
    r[("POST", f"{AS}/register")] = js(201, {"client_id": "cid", "token_endpoint_auth_method":
                                             "none"})  # fmt: skip

    def token(body, headers):
        seen["token"] = dict(x.split("=", 1) for x in body.decode().split("&"))
        return js(200, tokens)

    r[("POST", f"{AS}/token")] = token
    return r


def browser(state_override=None):
    """Plays the user agent: follow the authorize URL's redirect_uri with a code."""

    def show(url):
        from urllib.parse import parse_qs, urlencode, urlsplit

        q = {k: v[0] for k, v in parse_qs(urlsplit(url).query).items()}
        show.q = q
        cb = q["redirect_uri"] + "?" + urlencode({"code": "the-code",
                                                   "state": state_override or q["state"],
                                                   "iss": AS})  # fmt: skip
        threading.Thread(target=_hit, args=(cb,), daemon=True).start()

    return show


def test_login_flow_pkce_resource_state():
    seen: dict = {}
    toks = {"access_token": "AT", "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": "RT", "scope": "read offline_access"}  # fmt: skip
    show = browser()
    ts = mcpoauth.login(mcpoauth.LoginConfig(SRV, timeout=10), show,
                        http=FakeHttp(flow_routes(toks, seen)), now=lambda: 1000.0)  # fmt: skip
    q = show.q
    assert q["response_type"] == "code" and q["code_challenge_method"] == "S256"
    assert q["resource"] == SRV and q["scope"] == "read offline_access" and q["client_id"] == "cid"
    t = seen["token"]
    assert t["grant_type"] == "authorization_code" and t["code"] == "the-code"
    assert mcpoauth.pkce_challenge(t["code_verifier"]) == q["code_challenge"]
    assert t["resource"] == "https%3A%2F%2Fmcp.example.com%2Fmcp" and t["client_id"] == "cid"
    assert ts["access_token"] == "AT" and ts["refresh_token"] == "RT"
    assert ts["expires_at"] == 4600 and ts["token_endpoint"] == f"{AS}/token"
    assert (
        ts["resource"] == SRV and ts["issuer"] == AS and ts["scopes"] == ["read", "offline_access"]
    )
    assert mcpoauth.endpoint_hosts(ts) == ["auth.example.com"]


def test_login_flow_state_mismatch_no_token_request():
    seen: dict = {}
    with pytest.raises(OAuthError, match="state mismatch"):
        mcpoauth.login(mcpoauth.LoginConfig(SRV, timeout=10), browser("forged"),
                       http=FakeHttp(flow_routes({}, seen)))  # fmt: skip
    assert "token" not in seen


def test_login_preregistered_client_no_dcr():
    seen: dict = {}
    r = flow_routes({"access_token": "A", "token_type": "bearer"}, seen)
    del r[("POST", f"{AS}/register")]
    meta = {**AS_META, "registration_endpoint": None}
    r[("GET", ASM_URL)] = js(200, meta)
    h = FakeHttp(r)
    ts = mcpoauth.login(mcpoauth.LoginConfig(SRV, client_id="pre", client_secret="s3",
                                             timeout=10), browser(), http=h)  # fmt: skip
    assert ts["client_id"] == "pre" and ts["auth_method"] == "client_secret_basic"
    tok_req = [x for x in h.seen if x[1] == f"{AS}/token"][0]
    assert tok_req[3]["Authorization"].startswith("Basic ")
    assert ts["refresh_token"] is None and ts["expires_at"] is None


# ---------------------------------------------------------------- token-set size


def ts_of(size_access: int, size_refresh: int = 40) -> dict:
    return {"v": 1, "login_id": "l", "obtained_at": "2026-09-23T00:00:00+00:00",
            "resource": SRV, "issuer": AS, "token_endpoint": f"{AS}/token",
            "revocation_endpoint": f"{AS}/revoke", "client_id": "cid", "client_secret": None,
            "auth_method": "none", "scopes": ["read"], "access_token": "a" * size_access,
            "expires_at": 5, "refresh_token": "r" * size_refresh}  # fmt: skip


def test_fit_under_cap_full():
    text, minimal = mcpoauth.fit(ts_of(100), 1500)
    assert not minimal and json.loads(text)["access_token"] == "a" * 100
    assert "client_secret" not in json.loads(text)  # None values dropped
    assert mcpoauth.fit(ts_of(5000), None)[1] is False  # op/env: no cap


def test_fit_over_cap_keeps_refresh_data_only():
    text, minimal = mcpoauth.fit(ts_of(1400), 1500)
    d = json.loads(text)
    assert minimal and len(text.encode()) <= 1500
    assert "access_token" not in d and d["refresh_token"] == "r" * 40
    assert set(d) <= set(mcpoauth.REFRESH_KEYS) and d["token_endpoint"] == f"{AS}/token"


def test_fit_over_cap_even_minimal_points_to_op():
    with pytest.raises(OAuthError, match="op backend"):
        mcpoauth.fit(ts_of(1400, 1600), 1500)
    no_rt = ts_of(1600)
    no_rt["refresh_token"] = None
    with pytest.raises(OAuthError, match="no refresh token"):
        mcpoauth.fit(no_rt, 1500)


def test_revoke_current_refresh_and_access():
    seen = []

    def rv(body, headers):
        seen.append(body.decode())
        return js(200, {})

    ts = ts_of(10)
    assert mcpoauth.revoke(FakeHttp({("POST", f"{AS}/revoke"): rv}), ts) == "ok"
    assert "token_type_hint=refresh_token" in seen[0] and "client_id=cid" in seen[0]
    assert "token_type_hint=access_token" in seen[1] and len(seen) == 2
    assert mcpoauth.revoke(FakeHttp({}), {**ts, "revocation_endpoint": None}) == "not advertised"
    assert mcpoauth.revoke(FakeHttp({}), ts).startswith("failed (refresh_token: HTTP 404")


def test_logout_current_set_prefers_volume_of_same_login():
    from agentbox import mcpcmd

    backend = {**ts_of(1), "refresh_token": "RT-old"}
    vol = {**backend, "refresh_token": "RT-rotated"}
    assert mcpcmd.current_set(backend, vol)["refresh_token"] == "RT-rotated"
    assert mcpcmd.current_set(backend, {**vol, "login_id": "older"}) is backend
    assert mcpcmd.current_set(None, vol) is vol and mcpcmd.current_set(backend, None) is backend


def test_minimal_set_keeps_revocation_endpoint():
    d = json.loads(mcpoauth.fit(ts_of(1400), 1500)[0])
    assert d["revocation_endpoint"] == f"{AS}/revoke"


@pytest.mark.parametrize("host", ["10.0.0.5", "auth.internal", "localhost"])
def test_login_refuses_unreachable_endpoint_hosts(host):
    with pytest.raises(OAuthError, match="gateway allowlist"):
        mcpoauth.endpoint_host_check({**AS_META, "token_endpoint": f"https://{host}/token"})
    mcpoauth.endpoint_host_check(AS_META)


def test_test_hooks_only_when_enabled(monkeypatch, tmp_path):
    monkeypatch.setenv(mcpoauth.CONNECT_ENV, "a.example:443=127.0.0.1:9")
    monkeypatch.setenv(mcpoauth.CA_ENV, str(tmp_path / "missing.pem"))
    h = mcpoauth.Http()  # production default: hooks ignored
    assert h.cmap == {}
    with pytest.raises(OAuthError, match="cannot load"):
        mcpoauth.Http(test_hooks=True)
    monkeypatch.delenv(mcpoauth.CA_ENV)
    assert mcpoauth.Http(test_hooks=True).cmap == {("a.example", 443): ("127.0.0.1", 9)}
    for bad in ("garbage", "a.example:x=1.2.3.4:5", "a.example:443=1.2.3.4"):
        monkeypatch.setenv(mcpoauth.CONNECT_ENV, bad)
        with pytest.raises(OAuthError, match="bad entry"):
            mcpoauth.Http(test_hooks=True)


def test_mcpcmd_hooks_follow_backend():
    from agentbox import mcpcmd

    assert mcpcmd.http_client(paths.Config(secret_backend="env")).cmap is not None
    assert mcpcmd.http_client(paths.Config()).ctx is not None


def test_http_overall_deadline(monkeypatch):
    """A server that accepts and never answers (TLS handshake stalls)."""
    import socket
    import time

    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    port = srv.getsockname()[1]
    monkeypatch.setenv(mcpoauth.CONNECT_ENV, f"slow.example:443=127.0.0.1:{port}")
    h = mcpoauth.Http(timeout=30, deadline=1.0, test_hooks=True)
    t0 = time.monotonic()
    with pytest.raises(OAuthError, match="within 1 s"):
        h.request("GET", "https://slow.example/x")
    assert time.monotonic() - t0 < 5
    srv.close()


def test_loopback_idle_connection_does_not_block_callback():
    import socket
    import time

    with mcpoauth.LoopbackServer("st") as lb:
        idle = socket.create_connection(("127.0.0.1", lb.port))  # never sends a byte
        half = socket.create_connection(("127.0.0.1", lb.port))
        half.sendall(b"GET /callback?code=x")  # partial request line, then silence
        t0 = time.monotonic()
        assert _hit(lb.redirect_uri + "?code=real&state=st") == 200
        assert lb.wait(5)["code"] == "real"
        assert time.monotonic() - t0 < 3
    # __exit__ returned although two connections are still open
    idle.close()
    half.close()


def test_loopback_wait_bounded_with_idle_connection():
    import socket
    import time

    t0 = time.monotonic()
    with mcpoauth.LoopbackServer("st") as lb:
        s = socket.create_connection(("127.0.0.1", lb.port))
        with pytest.raises(OAuthError, match="within"):
            lb.wait(0.5)
    assert time.monotonic() - t0 < 3
    s.close()


# ---------------------------------------------------------------- profile, delivery, render

OAUTH = {"url": SRV, "auth": "oauth", "tools": ["search"]}


def prof(servers, secrets=None):
    d = {"mount": [{"host": "/work/a", "mode": "rw"}], "mcp": {"servers": servers}}
    if secrets:
        d["secrets"] = secrets
    p = parse_profile(d, "demo")
    mounts = [m.__class__(**{**m.__dict__, "host_real": m.host}) for m in p.mounts]
    return p.__class__(**{**p.__dict__, "mounts": mounts})


def test_profile_oauth_fields_and_token_secret():
    p = prof({"lin-ear": {**OAUTH, "scopes": ["read", "write"], "client_id": "abc",
                          "client_secret": "LIN_SECRET"}})  # fmt: skip
    s = p.mcp_servers["lin-ear"]
    assert (
        s.scopes == ["read", "write"] and s.client_id == "abc" and s.client_secret == "LIN_SECRET"
    )
    ts = p.secrets["_MCP_OAUTH_LIN_EAR"]
    assert ts.to == ["mcp-gateway"] and ts.scope == "profile"
    assert ts.ref == "keychain:agentbox/demo/_MCP_OAUTH_LIN_EAR"
    assert p.secrets["LIN_SECRET"].to == ["mcp-gateway"]  # never the agent by inference


@pytest.mark.parametrize("server, secrets, msg", [
    ({"url": SRV, "scopes": ["a"]}, None, 'need auth = "oauth"'),
    ({**OAUTH, "client_secret": "X"}, None, "needs client_id"),
    ({**OAUTH, "scopes": ["bad scope"]}, None, "invalid value"),
    ({**OAUTH, "scopes": []}, None, "must not be empty"),
    ({**OAUTH, "client_id": "a\tb"}, None, "control"),
    (OAUTH, {"_MCP_OAUTH_S": {}}, "reserved"),
])  # fmt: skip
def test_profile_oauth_refusals(server, secrets, msg):
    with pytest.raises(ProfileError, match=msg):
        prof({"s": server}, secrets)


def test_profile_oauth_item_name_clash():
    with pytest.raises(ProfileError, match="same item name"):
        prof({"a-b": OAUTH, "a.b": OAUTH})


def ctx(tmp_path, p):
    return compose.Ctx(p, 7, network.DEFAULT_BASE, tmp_path, "a", "e", "g", gateway_image="gw:1")


def test_render_oauth_volume_gateway_only(tmp_path):
    p = prof({"lin": OAUTH})
    doc = compose.render(ctx(tmp_path, p))
    assert doc["volumes"]["mcpoauth"] == {"name": "agentbox-demo-mcp-oauth"}
    assert "mcpoauth:/var/lib/mcp-oauth" in doc["services"]["mcp-gateway"]["volumes"]
    for n, svc in doc["services"].items():
        if n != "mcp-gateway":
            assert "mcpoauth" not in json.dumps(svc.get("volumes", []))
    cfg = mcpgw.gateway_config(p)
    assert cfg["profile"] == "demo" and cfg["servers"]["lin"]["oauth_env"] == "_MCP_OAUTH_LIN"
    assert "mcpoauth" not in compose.render(ctx(tmp_path, prof({})))["volumes"]


def test_oauth_hosts_join_gateway_allowlist(tmp_path):
    p = prof({"lin": OAUTH})
    assert mcpgw.egress_domains(p, tmp_path) == ["mcp.example.com"]
    (tmp_path / mcpgw.OAUTH_HOSTS_FILE).write_text(json.dumps({
        "lin": {"hosts": ["auth.example.com", "10.0.0.1", "bad host"]},
        "gone": {"hosts": ["old.example.com"]}}))  # fmt: skip
    assert mcpgw.egress_domains(p, tmp_path) == ["auth.example.com", "mcp.example.com"]
    (tmp_path / mcpgw.OAUTH_HOSTS_FILE).write_text("not json")
    assert mcpgw.egress_domains(p, tmp_path) == ["mcp.example.com"]


def test_delivery_token_set_gateway_only(tmp_path):
    p = prof({"lin": {**OAUTH, "client_id": "c", "client_secret": "LIN_SEC"}})
    vals = {"_MCP_OAUTH_LIN": json.dumps(ts_of(5)), "LIN_SEC": "s"}
    d = delivery.collect(p, paths.Config(), tmp_path, fetch=lambda r: vals.get(r.split("/")[-1]))
    assert d.names_for("mcp-gateway") == ["LIN_SEC", "MCP_GATEWAY_TOKEN", "_MCP_OAUTH_LIN"]
    assert d.names_for("agent") == ["MCP_GATEWAY_TOKEN"]
    missing = delivery.collect(p, paths.Config(), tmp_path, fetch=lambda r: None).missing
    assert {m.name for m in missing} - {"CLAUDE_CODE_OAUTH_TOKEN"} == {"_MCP_OAUTH_LIN", "LIN_SEC"}


def test_missing_login_hint(capsys):
    from agentbox import box as boxmod

    p = prof({"lin": OAUTH})
    d = delivery.Delivery(missing=[delivery.Missing("_MCP_OAUTH_LIN", "x", ["mcp-gateway"])])
    boxmod.secret_problems(d, p)
    err = capsys.readouterr().err
    assert "MCP server lin is not logged in" in err and "agentbox mcp login demo lin" in err


def test_mcpcmd_store_cap():
    from agentbox import mcpcmd, secretstore

    assert mcpcmd.store_cap(secretstore.OWNED + "agentbox/p/_MCP_OAUTH_X") == 1500
    assert mcpcmd.store_cap("env:X") is None


def test_discover_legacy_origin_as_without_prm():
    """2025-03-26 servers (no RFC 9728): the AS is the server origin."""
    origin_meta = {**AS_META, "issuer": "https://mcp.example.com"}
    om = "https://mcp.example.com/.well-known/oauth-authorization-server"
    r = {("POST", SRV): js(401, {}, {"WWW-Authenticate": 'Bearer realm="OAuth"'}),
         ("GET", om): js(200, origin_meta)}  # fmt: skip
    d = mcpoauth.discover(FakeHttp(r), SRV)
    assert d.issuer == "https://mcp.example.com" and d.resource == SRV
    r[("GET", om)] = js(200, {**origin_meta, "issuer": "https://other.example"})
    with pytest.raises(OAuthError, match="no protected resource metadata"):
        mcpoauth.discover(FakeHttp(r), SRV)
