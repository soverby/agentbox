"""OAuth for MCP upstreams, on the host (PLAN §2.6, P6b). Stdlib only.

MCP authorization, revision 2026-07-28
(https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization):

- Protected-resource metadata (RFC 9728): the `resource_metadata` URL of the
  server's 401 `WWW-Authenticate`, else the well-known URIs with the path,
  then at the root ("Authorization Server Discovery" §Protected Resource
  Metadata Discovery Requirements).
- Authorization-server metadata: RFC 8414 / OIDC discovery, in the spec's
  order (path insertion first); `issuer` must equal the issuer used to build
  the URL (§Authorization Server Metadata Discovery).
- PKCE S256 only; refuse when `code_challenge_methods_supported` lacks S256
  ("Security Considerations" §Authorization Code Protection).
- Client: the profile's pre-registered `client_id`, else dynamic client
  registration (RFC 7591, `application_type: native`) ("Client
  Registration" priority 1 and 3; Client ID Metadata Documents need an
  https-hosted document, which agentbox does not have).
- `resource` (RFC 8707) in the authorization and token requests (§Resource
  Parameter Implementation); scopes: profile `scopes`, else the 401
  challenge's `scope`, else PRM `scopes_supported` (§Scope Selection
  Strategy); `offline_access` added when the AS lists it (§Refresh Tokens).
- `state` check, and `iss` check per RFC 9207 (§Authorization Response
  Validation). Loopback redirect `http://127.0.0.1:<port>/callback`.

Every URL from metadata must be https. Redirects are not followed (a
metadata GET may follow up to 3 https -> https redirects). Responses are
size-capped. Test-only overrides (env): AGENTBOX_TEST_OAUTH_CA (extra CA
file), AGENTBOX_TEST_OAUTH_CONNECT ("host:port=ip:port,..." connect map).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import http.client
import http.server
import json
import os
import re
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from urllib.parse import parse_qs, quote, urlencode, urlsplit, urlunsplit

from . import term

MAX_BODY = 256 * 1024
TIMEOUT = 20.0
DEADLINE = 30.0  # whole exchange (connect, send, headers, body)
LOGIN_TIMEOUT = 300.0
VERSION = 1
CA_ENV = "AGENTBOX_TEST_OAUTH_CA"
CONNECT_ENV = "AGENTBOX_TEST_OAUTH_CONNECT"
USER_AGENT = "agentbox-mcp-login/1"
ERR_CODE_RE = re.compile(r"[A-Za-z0-9_.-]{1,64}")


class OAuthError(Exception):
    pass


def clean(s: object, n: int = 200) -> str:
    return term.clean(" ".join(str(s).split()))[:n]


# ---------------------------------------------------------------- URLs


def https_url(u: object, what: str) -> str:
    """An absolute https URL without userinfo or fragment (metadata is untrusted)."""
    if not isinstance(u, str) or len(u) > 2048:
        raise OAuthError(f"{what}: not a URL string")
    if any(c.isspace() or ord(c) < 0x20 or ord(c) == 0x7F for c in u):
        raise OAuthError(f"{what}: URL has whitespace or control characters")
    p = urlsplit(u)
    if p.scheme != "https":
        raise OAuthError(f"{what}: {clean(u)} is not https")
    if not p.hostname or "@" in p.netloc or p.fragment:
        raise OAuthError(f"{what}: {clean(u)} is not a plain https URL")
    try:
        p.port  # noqa: B018 (raises on a bad port)
    except ValueError:
        raise OAuthError(f"{what}: {clean(u)} has a bad port") from None
    return u


def origin(u: str) -> str:
    p = urlsplit(u)
    return urlunsplit((p.scheme, p.netloc, "", "", ""))


def canonical_resource(u: str) -> str:
    """RFC 8707 / MCP canonical server URI: lowercase scheme and host, no
    fragment, no trailing slash (unless the path is only '/')."""
    p = urlsplit(u)
    host = (p.hostname or "").lower()
    netloc = host if p.port in (None, 443) else f"{host}:{p.port}"
    path = p.path.rstrip("/")
    return urlunsplit(("https", netloc, path, p.query, ""))


def well_known_prm(server_url: str) -> list[str]:
    """RFC 9728 §3.1 well-known URIs: with the path, then the root."""
    p = urlsplit(server_url)
    base = urlunsplit((p.scheme, p.netloc, "", "", ""))
    path = p.path.rstrip("/")
    out = []
    if path:
        out.append(f"{base}/.well-known/oauth-protected-resource{path}")
    out.append(f"{base}/.well-known/oauth-protected-resource")
    return out


def well_known_as(issuer: str) -> list[str]:
    """MCP order: RFC 8414 path insertion, OIDC path insertion, OIDC append."""
    p = urlsplit(issuer)
    base = urlunsplit((p.scheme, p.netloc, "", "", ""))
    path = p.path.rstrip("/")
    if path:
        return [
            f"{base}/.well-known/oauth-authorization-server{path}",
            f"{base}/.well-known/openid-configuration{path}",
            f"{base}{path}/.well-known/openid-configuration",
        ]
    return [f"{base}/.well-known/oauth-authorization-server",
            f"{base}/.well-known/openid-configuration"]  # fmt: skip


# ---------------------------------------------------------------- WWW-Authenticate

_TOKEN = r"[!#$%&'*+.^_`|~0-9A-Za-z-]+"
_PARAM = re.compile(rf"\s*({_TOKEN})\s*=\s*(\"(?:[^\"\\]|\\.)*\"|{_TOKEN})\s*")


def parse_www_authenticate(header: str) -> dict[str, str]:
    """Parameters of the Bearer challenge (RFC 9110 §11.6.1 / RFC 6750 §3).
    Other schemes are skipped. Keys are lowercase; quoted values unescaped."""
    out: dict[str, str] = {}
    s = header or ""
    i = 0
    scheme = None
    while i < len(s):
        m = re.compile(rf"\s*,?\s*({_TOKEN})(?=\s|$|,)").match(s, i)
        if m and not re.match(r"\s*=", s[m.end() :]):
            scheme = m.group(1).lower()
            i = m.end()
            continue
        m = _PARAM.match(s, i)
        if not m:
            i += 1
            continue
        k, v = m.group(1).lower(), m.group(2)
        if v.startswith('"'):
            v = re.sub(r"\\(.)", r"\1", v[1:-1])
        if scheme == "bearer" and k not in out:
            out[k] = v
        i = m.end()
        if i < len(s) and s[i] == ",":
            i += 1
    return out


# ---------------------------------------------------------------- HTTP


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes

    def json(self, what: str) -> dict:
        try:
            data = json.loads(self.body.decode("utf-8"))
        except (UnicodeDecodeError, ValueError):
            raise OAuthError(f"{what}: response is not JSON (HTTP {self.status})") from None
        if not isinstance(data, dict):
            raise OAuthError(f"{what}: response is not a JSON object")
        return data


def _connect_map(enabled: bool) -> dict[tuple[str, int], tuple[str, int]]:
    """Test-only connect map; honoured only with the env (test) secret backend."""
    raw = os.environ.get(CONNECT_ENV, "") if enabled else ""
    out = {}
    for item in filter(None, raw.split(",")):
        try:
            src, _, dst = item.partition("=")
            h, _, p = src.rpartition(":")
            dh, _, dp = dst.rpartition(":")
            if not h or not dh:
                raise ValueError
            out[(h.lower(), int(p))] = (dh, int(dp))
        except ValueError:
            raise OAuthError(
                f"{CONNECT_ENV}: bad entry {clean(item)} (want host:port=ip:port)"
            ) from None
    return out


def ssl_context(enabled: bool = False) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ca = os.environ.get(CA_ENV) if enabled else None
    if ca:
        try:
            ctx.load_verify_locations(cafile=ca)
        except (OSError, ssl.SSLError) as e:
            raise OAuthError(f"{CA_ENV}: cannot load {clean(ca)}: {type(e).__name__}") from None
    return ctx


def _no_proxy(host: str) -> bool:
    np = os.environ.get("NO_PROXY") or os.environ.get("no_proxy") or ""
    for d in (x.strip().lower() for x in np.split(",") if x.strip()):
        if d == "*" or host == d.lstrip(".") or host.endswith("." + d.lstrip(".")):
            return True
    return False


class _Conn(http.client.HTTPSConnection):
    """HTTPS with SNI + verification for the URL host; the TCP target may be
    remapped by the test-only connect map."""

    def __init__(self, host, port, target, **kw):
        super().__init__(host, port, **kw)
        self._target = target

    def connect(self):
        # The TLS socket is set on self.sock before the handshake, so the
        # overall deadline (shutdown of conn.sock) also ends a stalled handshake.
        if self._tunnel_host:
            http.client.HTTPConnection.connect(self)  # TCP to the proxy + CONNECT
            name = self._tunnel_host
        else:
            self.sock = socket.create_connection(self._target or (self.host, self.port),
                                                 self.timeout)  # fmt: skip
            name = self.host
        tls = self._context.wrap_socket(self.sock, server_hostname=name,
                                        do_handshake_on_connect=False)  # fmt: skip
        self.sock = tls
        tls.do_handshake()


class Http:
    """Minimal HTTPS client: https only, no redirects, capped bodies.
    Honours HTTPS_PROXY / NO_PROXY (CONNECT tunnel)."""

    def __init__(self, timeout: float = TIMEOUT, max_body: int = MAX_BODY,
                 test_hooks: bool = False, deadline: float = DEADLINE):  # fmt: skip
        """test_hooks: honour AGENTBOX_TEST_OAUTH_CA / _CONNECT (callers pass
        True only for the env secret backend, i.e. tests)."""
        self.timeout = timeout
        self.deadline = deadline
        self.max_body = max_body
        self.ctx = ssl_context(test_hooks)
        self.cmap = _connect_map(test_hooks)

    def request(self, method: str, url: str, body: bytes | None = None,
                headers: dict[str, str] | None = None) -> Response:  # fmt: skip
        https_url(url, "request")
        p = urlsplit(url)
        host, port = p.hostname.lower(), p.port or 443
        target = self.cmap.get((host, port))
        proxy = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
        if proxy and target is None and not _no_proxy(host):
            pp = urlsplit(proxy if "://" in proxy else f"http://{proxy}")
            conn = _Conn(pp.hostname, pp.port or 80, None, timeout=self.timeout, context=self.ctx)
            conn.set_tunnel(host, port)
        else:
            conn = _Conn(host, port, target, timeout=self.timeout, context=self.ctx)
        path = p.path or "/"
        if p.query:
            path += "?" + p.query
        h = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
        expired = threading.Event()

        def kill():  # overall deadline: a slow drip cannot extend the exchange
            expired.set()
            sock = conn.sock
            if sock is not None:
                with contextlib.suppress(OSError):
                    sock.shutdown(socket.SHUT_RDWR)

        timer = threading.Timer(self.deadline, kill)
        timer.daemon = True
        timer.start()
        try:
            conn.request(method, path, body=body, headers=h)
            r = conn.getresponse()
            data = r.read(self.max_body + 1)
            if expired.is_set():
                raise OSError("deadline")
            if len(data) > self.max_body:
                raise OAuthError(f"{clean(url)}: response larger than {self.max_body} bytes")
            return Response(r.status, {k.lower(): v for k, v in r.getheaders()}, data)
        except (OSError, http.client.HTTPException, ValueError) as e:
            if expired.is_set():
                raise OAuthError(f"{clean(url)}: no complete answer within "
                                 f"{int(self.deadline)} s") from None  # fmt: skip
            raise OAuthError(f"{clean(url)}: {type(e).__name__}: {clean(e, 120)}") from None
        finally:
            timer.cancel()
            conn.close()

    def get_json(self, url: str, what: str, redirects: int = 3) -> tuple[int, dict | None]:
        """GET a metadata document. (status, doc); doc None when not 200.
        Follows at most `redirects` https -> https redirects."""
        for _ in range(redirects + 1):
            r = self.request("GET", url)
            if r.status in (301, 302, 303, 307, 308):
                loc = r.headers.get("location", "")
                if loc.startswith("/"):
                    loc = origin(url) + loc
                url = https_url(loc, f"{what} redirect")
                continue
            if r.status != 200:
                return r.status, None
            return 200, r.json(what)
        raise OAuthError(f"{what}: too many redirects")

    def post_form(self, url: str, form: dict[str, str], headers: dict | None = None) -> Response:
        body = urlencode(form).encode()
        h = {"Content-Type": "application/x-www-form-urlencoded", **(headers or {})}
        return self.request("POST", url, body, h)

    def post_json(self, url: str, doc: dict) -> Response:
        return self.request("POST", url, json.dumps(doc).encode(),
                            {"Content-Type": "application/json"})  # fmt: skip


# ---------------------------------------------------------------- discovery


@dataclass
class Discovery:
    server_url: str
    resource: str
    issuer: str
    as_meta: dict
    challenge_scope: list[str] | None = None
    prm_scopes: list[str] | None = None


INIT_BODY = {
    "jsonrpc": "2.0", "id": 1, "method": "initialize",
    "params": {"protocolVersion": "2025-11-25", "capabilities": {},
               "clientInfo": {"name": "agentbox-mcp-login", "version": "1"}},
}  # fmt: skip


def _scopes(v: object) -> list[str] | None:
    if isinstance(v, str):
        v = v.split()
    if isinstance(v, list) and all(isinstance(x, str) for x in v):
        from .profile import SCOPE_RE

        return [x for x in v if SCOPE_RE.fullmatch(x)] or None
    return None


def check_resource(prm_resource: object, server_url: str) -> str:
    """RFC 9728 §3.3 / §7.3: the metadata's `resource` must name this server:
    same origin, and a path prefix of the server URL (servers often name their
    root). Returns the canonical resource for the `resource` parameter."""
    res = https_url(prm_resource, "protected resource metadata `resource`")
    a, b = canonical_resource(res), canonical_resource(server_url)
    if origin(a) != origin(b):
        raise OAuthError(f"protected resource metadata names {clean(res)}, not this server")
    pa, pb = urlsplit(a).path, urlsplit(b).path
    if pa and pb != pa and not pb.startswith(pa + "/"):
        raise OAuthError(f"protected resource metadata names {clean(res)}, not this server")
    return a


def as_metadata(http: Http, issuer: str) -> dict:
    issuer = https_url(issuer, "authorization server")
    tried = []
    for u in well_known_as(issuer):
        st, doc = http.get_json(u, "authorization server metadata")
        tried.append(f"{u} -> {st}")
        if doc is None:
            continue
        if doc.get("issuer") != issuer:
            raise OAuthError(
                f"authorization server metadata at {clean(u)} has issuer "
                f"{clean(doc.get('issuer'))}, not {clean(issuer)} (RFC 8414 §3.3)"
            )
        return doc
    raise OAuthError("no authorization server metadata: " + "; ".join(tried))


def validate_as(meta: dict, need_registration: bool) -> None:
    for k in ("authorization_endpoint", "token_endpoint"):
        if k not in meta:
            raise OAuthError(f"authorization server metadata has no {k}")
        https_url(meta[k], k)
    for k in ("registration_endpoint", "revocation_endpoint"):
        if meta.get(k) is not None:
            https_url(meta[k], k)
    methods = meta.get("code_challenge_methods_supported")
    if not isinstance(methods, list) or "S256" not in methods:
        raise OAuthError(
            "the authorization server does not advertise PKCE S256 "
            "(code_challenge_methods_supported); agentbox refuses to continue"
        )
    if need_registration and not meta.get("registration_endpoint"):
        raise OAuthError(
            "the authorization server has no dynamic client registration: register a client "
            "with the provider and set client_id (and client_secret) in [mcp.servers.<name>]"
        )


def discover(http: Http, server_url: str) -> Discovery:
    server_url = https_url(server_url, "MCP server url")
    hdrs = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    r = http.request("POST", server_url, json.dumps(INIT_BODY).encode(), hdrs)
    if r.status != 401:
        raise OAuthError(
            f"the MCP server answered HTTP {r.status} without a token, not 401: it does not "
            'ask for OAuth (use no auth, or bearer = "<SECRET>")'
        )
    ch = parse_www_authenticate(r.headers.get("www-authenticate", ""))
    urls = []
    if ch.get("resource_metadata"):
        urls.append(https_url(ch["resource_metadata"], "resource_metadata"))
    else:
        urls = well_known_prm(server_url)
    prm, tried = None, []
    for u in urls:
        st, doc = http.get_json(u, "protected resource metadata")
        tried.append(f"{u} -> {st}")
        if doc is not None:
            prm = doc
            break
    if prm is None:
        # Servers of the 2025-03-26 revision have no RFC 9728 document: their
        # AS is the server's origin (that revision's "authorization base
        # URL"). Only when the challenge names no resource_metadata; the
        # issuer check below still applies.
        if ch.get("resource_metadata"):
            raise OAuthError("no protected resource metadata (RFC 9728): " + "; ".join(tried))
        prm = {"resource": canonical_resource(server_url),
               "authorization_servers": [origin(server_url)]}  # fmt: skip
        try:
            as_metadata(http, origin(server_url))
        except OAuthError:
            raise OAuthError(
                "no protected resource metadata (RFC 9728): " + "; ".join(tried)
            ) from None
    resource = check_resource(prm.get("resource"), server_url)
    servers = prm.get("authorization_servers")
    if not isinstance(servers, list) or not servers:
        raise OAuthError("protected resource metadata lists no authorization_servers")
    issuer = https_url(servers[0], "authorization_servers[0]")
    meta = as_metadata(http, issuer)
    return Discovery(server_url, resource, issuer, meta, _scopes(ch.get("scope")),
                     _scopes(prm.get("scopes_supported")))  # fmt: skip


def choose_scopes(d: Discovery, profile_scopes: list[str] | None) -> list[str]:
    s = list(profile_scopes or d.challenge_scope or d.prm_scopes or [])
    sup = d.as_meta.get("scopes_supported")
    if s and isinstance(sup, list) and "offline_access" in sup and "offline_access" not in s:
        s.append("offline_access")
    return s


# ---------------------------------------------------------------- PKCE, DCR


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def pkce_challenge(verifier: str) -> str:
    """RFC 7636 §4.2 S256."""
    return b64url(hashlib.sha256(verifier.encode("ascii")).digest())


def pkce_pair() -> tuple[str, str]:
    v = b64url(secrets.token_bytes(48))  # 64 chars, RFC 7636 §4.1: 43-128
    return v, pkce_challenge(v)


@dataclass
class ClientInfo:
    client_id: str
    client_secret: str | None = None
    auth_method: str = "none"


AUTH_METHODS = ("none", "client_secret_post", "client_secret_basic")


def register(http: Http, meta: dict, redirect_uri: str, scopes: list[str]) -> ClientInfo:
    """RFC 7591 dynamic client registration (native public client)."""
    req = {
        "client_name": "agentbox",
        "application_type": "native",
        "redirect_uris": [redirect_uri],
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    }
    if scopes:
        req["scope"] = " ".join(scopes)
    r = http.post_json(https_url(meta["registration_endpoint"], "registration_endpoint"), req)
    if r.status not in (200, 201):
        raise OAuthError(f"client registration failed: HTTP {r.status}{error_code(r)}")
    doc = r.json("client registration")
    cid = doc.get("client_id")
    if not isinstance(cid, str) or not cid or len(cid) > 512:
        raise OAuthError("client registration returned no client_id")
    sec = doc.get("client_secret")
    sec = sec if isinstance(sec, str) and sec else None
    method = doc.get("token_endpoint_auth_method") or ("client_secret_basic" if sec else "none")
    if method not in AUTH_METHODS:
        raise OAuthError(f"client registration: unsupported auth method {clean(method)}")
    if method != "none" and not sec:
        raise OAuthError(f"client registration: {method} without a client_secret")
    return ClientInfo(cid, sec, method)


def error_code(r: Response) -> str:
    """`: <error>` from an OAuth error body (RFC 6749 §5.2); the code only,
    never the description (untrusted, may echo request data)."""
    try:
        e = json.loads(r.body.decode()).get("error")
    except (ValueError, UnicodeDecodeError, AttributeError):
        return ""
    return f": {e}" if isinstance(e, str) and ERR_CODE_RE.fullmatch(e) else ""


def client_auth(c: ClientInfo, form: dict[str, str]) -> dict[str, str]:
    """Add client authentication (RFC 6749 §2.3.1); returns extra headers."""
    if c.auth_method == "client_secret_basic" and c.client_secret:
        raw = f"{quote(c.client_id, safe='')}:{quote(c.client_secret, safe='')}".encode()
        return {"Authorization": "Basic " + base64.b64encode(raw).decode()}
    form["client_id"] = c.client_id
    if c.auth_method == "client_secret_post" and c.client_secret:
        form["client_secret"] = c.client_secret
    return {}


# ---------------------------------------------------------------- loopback redirect


@dataclass
class Callback:
    params: dict[str, str] = field(default_factory=dict)
    error: str | None = None
    done: threading.Event = field(default_factory=threading.Event)


PAGE = b"<!doctype html><title>agentbox</title><p>agentbox: {msg} You can close this tab."


class LoopbackServer:
    """One-shot HTTP server on 127.0.0.1 for the authorization response.
    The first request to /callback ends the wait; `state` must match."""

    def __init__(self, state: str, port: int = 0):
        self.state = state
        self.cb = Callback()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                u = urlsplit(self.path)
                if u.path != "/callback" or outer.cb.done.is_set():
                    self.send_error(404)
                    return
                q = {k: v[0] for k, v in parse_qs(u.query, keep_blank_values=True).items()}
                got = q.get("state", "")
                if not secrets.compare_digest(got.encode(), outer.state.encode()):
                    outer.cb.error = "state mismatch: the authorization response was refused"
                    msg = b"login refused (state mismatch)."
                else:
                    outer.cb.params = q
                    msg = b"login received."
                body = PAGE.replace(b"{msg}", msg)
                self.send_response(200 if outer.cb.error is None else 400)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)
                outer.cb.done.set()

            def log_message(self, *a):
                pass

        H.timeout = 5  # an idle or slow connection cannot hold a handler

        class S(http.server.ThreadingHTTPServer):
            daemon_threads = True
            block_on_close = False

        self.srv = S(("127.0.0.1", port), H)
        self.port = self.srv.server_address[1]
        self.redirect_uri = f"http://127.0.0.1:{self.port}/callback"
        self.thread = threading.Thread(target=self.srv.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *a):
        self.srv.shutdown()
        self.srv.server_close()

    def wait(self, timeout: float) -> dict[str, str]:
        if not self.cb.done.wait(timeout):
            raise OAuthError(f"no authorization response within {int(timeout)} s")
        if self.cb.error:
            raise OAuthError(self.cb.error)
        return self.cb.params


def check_iss(meta: dict, issuer: str, params: dict[str, str]) -> None:
    """RFC 9207 §2.4 as the MCP spec's table (§Authorization Response Validation)."""
    iss = params.get("iss")
    if iss is None:
        if meta.get("authorization_response_iss_parameter_supported") is True:
            raise OAuthError("authorization response has no iss, but the server advertises it")
        return
    if iss != issuer:
        raise OAuthError("authorization response iss does not match the authorization server")


# ---------------------------------------------------------------- tokens


def token_response(r: Response, what: str) -> dict:
    if r.status != 200:
        raise OAuthError(f"{what} failed: HTTP {r.status}{error_code(r)}")
    doc = r.json(what)
    at = doc.get("access_token")
    if not isinstance(at, str) or not at:
        raise OAuthError(f"{what}: no access_token")
    if str(doc.get("token_type", "")).lower() != "bearer":
        raise OAuthError(f"{what}: token_type is not Bearer")
    return doc


def token_set(d: Discovery, c: ClientInfo, tok: dict, scopes: list[str], now: float) -> dict:
    exp = tok.get("expires_in")
    expires_at = int(now + exp) if isinstance(exp, int | float) and exp > 0 else None
    rt = tok.get("refresh_token")
    granted = _scopes(tok.get("scope")) or scopes
    return {
        "v": VERSION,
        "login_id": secrets.token_hex(8),
        "obtained_at": datetime.fromtimestamp(now, UTC).isoformat(timespec="seconds"),
        "resource": d.resource,
        "issuer": d.issuer,
        "token_endpoint": d.as_meta["token_endpoint"],
        "revocation_endpoint": d.as_meta.get("revocation_endpoint"),
        "client_id": c.client_id,
        "client_secret": c.client_secret,
        "auth_method": c.auth_method,
        "scopes": granted,
        "access_token": tok["access_token"],
        "expires_at": expires_at,
        "refresh_token": rt if isinstance(rt, str) and rt else None,
    }


REFRESH_KEYS = ("v", "login_id", "obtained_at", "resource", "issuer", "token_endpoint",
                "revocation_endpoint", "client_id", "client_secret", "auth_method",
                "refresh_token")  # fmt: skip


def dumps(ts: dict) -> str:
    return json.dumps({k: v for k, v in ts.items() if v is not None}, separators=(",", ":"))


def fit(ts: dict, cap: int | None) -> tuple[str, bool]:
    """The stored JSON under `cap` bytes (None: no cap). Too big: keep only
    what a refresh needs (the gateway gets an access token at start).
    Returns (json, minimal)."""
    full = dumps(ts)
    if cap is None or len(full.encode()) <= cap:
        return full, False
    if not ts.get("refresh_token"):
        raise OAuthError(
            f"the token set is {len(full.encode())} bytes and has no refresh token; the "
            f"keychain backend holds at most {cap}. Use the op backend."
        )
    small = dumps({k: ts.get(k) for k in REFRESH_KEYS})
    if len(small.encode()) > cap:
        raise OAuthError(
            f"even the refresh-only token set is {len(small.encode())} bytes; the keychain "
            f'backend holds at most {cap}. Use the op backend (secret_backend = "op").'
        )
    return small, True


def parse_token_set(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        ts = json.loads(raw)
    except ValueError:
        return None
    return ts if isinstance(ts, dict) and ts.get("v") == VERSION else None


def endpoint_host_check(meta: dict) -> None:
    """The gateway reaches the token / revocation endpoints through squid by
    name: refuse hosts squid would deny (IP literals, *.internal, ...)."""
    from .profile import hostname_problem

    for k in ("token_endpoint", "revocation_endpoint"):
        if meta.get(k):
            h = (urlsplit(meta[k]).hostname or "").lower()
            if msg := hostname_problem(h):
                raise OAuthError(
                    f"{k} host {clean(h)} cannot be on the gateway allowlist ({msg}); "
                    "agentbox cannot refresh tokens for this server"
                )


def endpoint_hosts(ts: dict) -> list[str]:
    out = []
    for k in ("token_endpoint", "revocation_endpoint"):
        if ts.get(k):
            h = urlsplit(ts[k]).hostname
            if h and h.lower() not in out:
                out.append(h.lower())
    return out


def revoke(http: Http, ts: dict) -> str:
    """Best-effort RFC 7009 revocation of the refresh and the access token of
    `ts`. "ok" only when every present token was revoked (HTTP 200)."""
    url = ts.get("revocation_endpoint")
    if not url:
        return "not advertised"
    toks = [(ts.get(k), k) for k in ("refresh_token", "access_token") if ts.get(k)]
    if not toks:
        return "no token to revoke"
    c = ClientInfo(ts["client_id"], ts.get("client_secret"), ts.get("auth_method", "none"))
    bad = []
    for tok, hint in toks:
        form = {"token": tok, "token_type_hint": hint}
        try:
            r = http.post_form(https_url(url, "revocation_endpoint"), form, client_auth(c, form))
        except OAuthError as e:
            bad.append(f"{hint}: {e}")
            continue
        if r.status != 200:
            bad.append(f"{hint}: HTTP {r.status}{error_code(r)}")
    return "ok" if not bad else "failed (" + "; ".join(bad) + ")"


# ---------------------------------------------------------------- the flow


@dataclass
class LoginConfig:
    server_url: str
    scopes: list[str] | None = None
    client_id: str | None = None
    client_secret: str | None = None
    redirect_port: int = 0
    timeout: float = LOGIN_TIMEOUT


def authorize_url(meta: dict, c: ClientInfo, redirect_uri: str, challenge: str, state: str,
                  resource: str, scopes: list[str]) -> str:  # fmt: skip
    q = {
        "response_type": "code",
        "client_id": c.client_id,
        "redirect_uri": redirect_uri,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
        "state": state,
        "resource": resource,
    }
    if scopes:
        q["scope"] = " ".join(scopes)
    ep = https_url(meta["authorization_endpoint"], "authorization_endpoint")
    return ep + ("&" if urlsplit(ep).query else "?") + urlencode(q)


def login(cfg: LoginConfig, show_url, http: Http | None = None, now=time.time) -> dict:
    """Run the flow. `show_url(url)` opens the browser and/or prints the URL.
    Returns the token set (dict)."""
    http = http or Http()
    d = discover(http, cfg.server_url)
    validate_as(d.as_meta, need_registration=cfg.client_id is None)
    endpoint_host_check(d.as_meta)
    scopes = choose_scopes(d, cfg.scopes)
    state = b64url(secrets.token_bytes(24))
    verifier, challenge = pkce_pair()
    with LoopbackServer(state, cfg.redirect_port) as lb:
        if cfg.client_id:
            method = "client_secret_basic" if cfg.client_secret else "none"
            sup = d.as_meta.get("token_endpoint_auth_methods_supported")
            if (
                cfg.client_secret
                and isinstance(sup, list)
                and method not in sup
                and "client_secret_post" in sup
            ):
                method = "client_secret_post"
            c = ClientInfo(cfg.client_id, cfg.client_secret, method)
        else:
            c = register(http, d.as_meta, lb.redirect_uri, scopes)
        show_url(authorize_url(d.as_meta, c, lb.redirect_uri, challenge, state, d.resource,
                               scopes))  # fmt: skip
        params = lb.wait(cfg.timeout)
    check_iss(d.as_meta, d.issuer, params)
    if "error" in params:
        e = params["error"]
        e = e if ERR_CODE_RE.fullmatch(e) else "invalid"
        raise OAuthError(f"the authorization server refused: {e}")
    code = params.get("code")
    if not code:
        raise OAuthError("authorization response has no code")
    form = {"grant_type": "authorization_code", "code": code, "redirect_uri": lb.redirect_uri,
            "code_verifier": verifier, "resource": d.resource}  # fmt: skip
    extra = client_auth(c, form)
    r = http.post_form(https_url(d.as_meta["token_endpoint"], "token_endpoint"), form, extra)
    tok = token_response(r, "token request")
    return token_set(d, c, tok, scopes, now())
