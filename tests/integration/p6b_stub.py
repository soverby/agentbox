"""Stub OAuth authorization server + protected MCP server for the P6b smoke.

Runs in a container (the mcp-gateway image: FastMCP, Starlette, uvicorn) on
the harness network, TLS with the test CA, two names on one process:

- https://stub.agentbox-test/mcp: the protected MCP server (tools `whoami`,
  `secret_tool`). No or unknown bearer -> 401 with
  `WWW-Authenticate: Bearer resource_metadata="…", scope="mcp:tools"`.
  Protected-resource metadata (RFC 9728) at
  /.well-known/oauth-protected-resource/mcp.
- https://auth.agentbox-test/as: the AS (issuer). RFC 8414 metadata at
  /.well-known/oauth-authorization-server/as; DCR /as/register; /as/authorize
  auto-approves (302 to the loopback redirect with code, state, iss); /as/token
  (authorization_code with PKCE S256 + resource check; refresh_token with
  rotation); /as/revoke (RFC 7009).
- /admin/expire: every access token stops working (forces a 401 -> refresh).
  /admin/revoke: every access and refresh token stops working.

Logs one JSON line per event to --log: never a token, only sha256 prefixes of
bearers seen on /mcp (so the smoke can prove which token arrived).

Usage: python3 p6b_stub.py --cert C --key K --log L
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import secrets
import threading
import time
from urllib.parse import parse_qs, urlencode

from fastmcp import FastMCP
from fastmcp.server.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

RS = "https://stub.agentbox-test"
RESOURCE = f"{RS}/mcp"
ISSUER = "https://auth.agentbox-test/as"
PRM_PATH = "/.well-known/oauth-protected-resource/mcp"
LOCK = threading.Lock()
DB = {"clients": {}, "codes": {}, "access": {}, "refresh": {}}


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


def log(**rec) -> None:
    with LOCK, open(ARGS.log, "a") as f:
        f.write(json.dumps({"t": round(time.time(), 3), **rec}) + "\n")


def as_meta() -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/authorize",
        "token_endpoint": f"{ISSUER}/token",
        "registration_endpoint": f"{ISSUER}/register",
        "revocation_endpoint": f"{ISSUER}/revoke",
        "code_challenge_methods_supported": ["S256"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "scopes_supported": ["mcp:tools", "offline_access"],
        "authorization_response_iss_parameter_supported": True,
    }


def issue(client_id: str, scope: str) -> dict:
    at, rt = "at-" + secrets.token_urlsafe(24), "rt-" + secrets.token_urlsafe(24)
    DB["access"][at] = {"client": client_id, "resource": RESOURCE}
    DB["refresh"][rt] = {"client": client_id, "scope": scope}
    return {"access_token": at, "token_type": "Bearer", "expires_in": 3600,
            "refresh_token": rt, "scope": scope}  # fmt: skip


def client_ok(form: dict) -> bool:
    c = DB["clients"].get(form.get("client_id", ""))
    return bool(c) and secrets.compare_digest(form.get("client_secret", ""), c["secret"])


async def oauth(request: Request) -> Response:
    p, m = request.url.path, request.method
    if p == PRM_PATH:
        return JSONResponse({"resource": RESOURCE, "authorization_servers": [ISSUER],
                             "scopes_supported": ["mcp:tools"]})  # fmt: skip
    if p == "/.well-known/oauth-authorization-server/as":
        return JSONResponse(as_meta())
    if p == "/as/register" and m == "POST":
        req = await request.json()
        cid, sec = "cid-" + secrets.token_hex(6), "cs-" + secrets.token_urlsafe(24)
        DB["clients"][cid] = {"secret": sec, "redirect_uris": req.get("redirect_uris", [])}
        log(ev="register", application_type=req.get("application_type"),
            redirect_uris=req.get("redirect_uris"), grant_types=req.get("grant_types"),
            auth=req.get("token_endpoint_auth_method"))  # fmt: skip
        # The AS issues a confidential client (RFC 7591 §3.2.1 lets it change the method).
        return JSONResponse(
            {
                "client_id": cid,
                "client_secret": sec,
                "token_endpoint_auth_method": "client_secret_post",
                "redirect_uris": req.get("redirect_uris", []),
            },
            status_code=201,
        )
    if p == "/as/authorize" and m == "GET":
        q = dict(request.query_params)
        c = DB["clients"].get(q.get("client_id", ""))
        ok = (c is not None and q.get("redirect_uri") in c["redirect_uris"]
              and q.get("code_challenge_method") == "S256" and q.get("code_challenge")
              and q.get("resource") == RESOURCE and q.get("response_type") == "code")  # fmt: skip
        log(ev="authorize", ok=bool(ok), resource=q.get("resource"), scope=q.get("scope"),
            method=q.get("code_challenge_method"), has_state=bool(q.get("state")))  # fmt: skip
        if not ok:
            return JSONResponse({"error": "invalid_request"}, status_code=400)
        code = "code-" + secrets.token_urlsafe(16)
        DB["codes"][code] = {
            "client": q["client_id"],
            "challenge": q["code_challenge"],
            "redirect_uri": q["redirect_uri"],
            "scope": q.get("scope", ""),
        }
        loc = q["redirect_uri"] + "?" + urlencode({"code": code, "state": q.get("state", ""),
                                                   "iss": ISSUER})  # fmt: skip
        return RedirectResponse(loc, status_code=302)
    if p == "/as/token" and m == "POST":
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        g = form.get("grant_type")
        rec = {"ev": "token", "grant": g, "resource": form.get("resource")}
        if not client_ok(form):
            log(**rec, ok=False, why="client")
            return JSONResponse({"error": "invalid_client"}, status_code=401)
        if g == "authorization_code":
            c = DB["codes"].pop(form.get("code", ""), None)
            v = form.get("code_verifier", "")
            ch = base64.urlsafe_b64encode(hashlib.sha256(v.encode()).digest()).rstrip(b"=")
            ok = (c is not None and c["client"] == form["client_id"]
                  and ch.decode() == c["challenge"] and form.get("resource") == RESOURCE
                  and form.get("redirect_uri") == c["redirect_uri"])  # fmt: skip
            log(**rec, ok=bool(ok), pkce=bool(c) and ch.decode() == c["challenge"])
            if not ok:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse(issue(form["client_id"], c["scope"]))
        if g == "refresh_token":
            r = DB["refresh"].pop(form.get("refresh_token", ""), None)  # rotation: one use
            ok = r is not None and r["client"] == form["client_id"]
            log(**rec, ok=bool(ok))
            if not ok:
                return JSONResponse({"error": "invalid_grant"}, status_code=400)
            return JSONResponse(issue(form["client_id"], r["scope"]))
        return JSONResponse({"error": "unsupported_grant_type"}, status_code=400)
    if p == "/as/revoke" and m == "POST":
        form = {k: v[0] for k, v in parse_qs((await request.body()).decode()).items()}
        t = form.get("token", "")
        hit = DB["refresh"].pop(t, None) is not None or DB["access"].pop(t, None) is not None
        log(ev="revoke", ok=client_ok(form), hint=form.get("token_type_hint"), known=hit)
        return Response(status_code=200)
    if p == "/admin/expire":
        n = len(DB["access"])
        DB["access"].clear()
        log(ev="admin-expire", n=n)
        return JSONResponse({"expired": n})
    if p == "/admin/revoke":
        n = len(DB["refresh"])
        DB["access"].clear()
        DB["refresh"].clear()
        log(ev="admin-revoke", n=n)
        return JSONResponse({"revoked": n})
    return JSONResponse({"error": "not_found"}, status_code=404)


class Record(Middleware):
    async def on_call_tool(self, context, call_next):
        from fastmcp.server.dependencies import get_http_headers

        h = get_http_headers(include_all=True)
        a = h.get("authorization", "")
        log(ev="tool", tool=context.message.name, auth=sha(a[7:]) if a[:7] == "Bearer " else "",
            agent_header="x-agentbox-probe" in h)  # fmt: skip
        return await call_next(context)


mcp = FastMCP("p6b-stub", middleware=[Record()])


@mcp.tool
def whoami() -> str:
    return "OAUTH-OK"


@mcp.tool
def secret_tool() -> str:
    return "SECRET-TOOL-RAN"


def build():
    inner = mcp.http_app(path="/mcp")

    async def app(scope, receive, send):
        if scope["type"] != "http":
            return await inner(scope, receive, send)
        path = scope["path"]
        if path.rstrip("/") == "/mcp":
            hdrs = {k.decode().lower(): v.decode() for k, v in scope["headers"]}
            a = hdrs.get("authorization", "")
            tok = a[7:] if a[:7] == "Bearer " else ""
            good = tok in DB["access"]
            log(ev="mcp", method=scope["method"], auth=sha(tok) if tok else "", ok=good)
            if not good:
                www = (f'Bearer resource_metadata="{RS}{PRM_PATH}", scope="mcp:tools"'
                       + (', error="invalid_token"' if tok else ""))  # fmt: skip
                r = JSONResponse({"error": "invalid_token"}, status_code=401,
                                 headers={"WWW-Authenticate": www})  # fmt: skip
                return await r(scope, receive, send)
            return await inner(scope, receive, send)
        resp = await oauth(Request(scope, receive))
        return await resp(scope, receive, send)

    return app


if __name__ == "__main__":
    import uvicorn

    ap = argparse.ArgumentParser()
    ap.add_argument("--cert", required=True)
    ap.add_argument("--key", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--port", type=int, default=443)
    ARGS = ap.parse_args()
    uvicorn.run(build(), host="0.0.0.0", port=ARGS.port, ssl_certfile=ARGS.cert,
                ssl_keyfile=ARGS.key, log_level="warning", lifespan="on")  # fmt: skip
