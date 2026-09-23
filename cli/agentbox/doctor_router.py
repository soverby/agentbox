"""Doctor checks for the model router (PLAN §2.5, §4 check 13, §5 P5).

- 13 (router): inside the real router container (Python, no curl): no
  external DNS, no direct TCP, via the proxy only the router allowlist (the
  `api_base` host names), no host ports. Same probe as the gateway's.
- 21 router-health: the container healthcheck (`/health/liveliness` on
  127.0.0.1, the only NO_PROXY target) is healthy.
- 21 router-routes: from the agent (the adversary's position) with the
  master key, the admin routes `/model/info`, `/config/yaml`, `/key/generate`
  (and `/config/update`, `/v1/model/info`) → 403/404; `/v1/models` → 200.
- 21 router-api-base: a chat request with `api_base: http://agent:9` is
  refused, and nothing connects to a listener on agent:9.
The agent reads the key from its own env (with-secrets): the value never
leaves the box and is never printed.
"""

from __future__ import annotations

import json

from . import box as boxmod
from . import compose, router

ADMIN_ROUTES = [
    ("GET", "/model/info"),
    ("GET", "/config/yaml"),
    ("POST", "/key/generate"),
    ("POST", "/config/update"),
    ("GET", "/v1/model/info"),
]

AGENT_PROBE = r"""
import json, os, socket, sys, threading, time, urllib.error, urllib.request
key = os.environ.get("AGENTBOX_ROUTER_MASTER_KEY", "")
model = sys.argv[1]
admin = json.loads(sys.argv[2])
op = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def call(method, path, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request("http://router:4000" + path, data=data, method=method,
        headers={"Authorization": "Bearer " + key, "Content-Type": "application/json"})
    try:
        with op.open(req, timeout=60) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except OSError as e:
        return "error " + type(e).__name__
if not key:
    print("FAIL 21 router-routes: no AGENTBOX_ROUTER_MASTER_KEY in the agent")
    print("FAIL 21 router-api-base: no AGENTBOX_ROUTER_MASTER_KEY in the agent")
    sys.exit(0)
bad = []
s = call("GET", "/v1/models")
if s != 200:
    bad.append(f"GET /v1/models -> {s} (want 200)")
for m, p in admin:
    s = call(m, p, {} if m == "POST" else None)
    if s not in (401, 403, 404):
        bad.append(f"{m} {p} -> {s} (want 403/404)")
print(("FAIL 21 router-routes: " + "; ".join(bad)) if bad else
      "PASS 21 router-routes: admin routes refused with the master key; /v1/models 200")
hits = []
try:
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", 9))
    srv.listen(8)
    srv.settimeout(0.5)
except OSError as e:
    srv = None
    listen_note = f"cannot listen on :9 ({e}); relied on the status only"
else:
    listen_note = "no connection to agent:9"
    def acc():
        end = time.time() + 20
        while time.time() < end:
            try:
                c, a = srv.accept()
                hits.append(a[0])
                c.close()
            except OSError:
                pass
    t = threading.Thread(target=acc, daemon=True)
    t.start()
s = call("POST", "/v1/chat/completions", {"model": model, "api_base": "http://agent:9",
         "messages": [{"role": "user", "content": "x"}], "max_tokens": 1})
time.sleep(2)
if srv is not None:
    srv.close()
if hits:
    print(f"FAIL 21 router-api-base: request with api_base http://agent:9 connected ({s})")
elif s in (400, 401, 403, 422):
    print(f"PASS 21 router-api-base: api_base in the body refused ({s}); {listen_note}")
else:
    print(f"FAIL 21 router-api-base: api_base in the body -> {s} (want 4xx); {listen_note}")
# header / key injection: the guard answers 400 before any upstream call
msgs = [{"role": "user", "content": "x"}]
bad = []
for path, body in (
    ("/v1/chat/completions", {"model": model, "messages": msgs, "max_tokens": 1,
     "extra_headers": {"Host": "evil.example", "X-Probe": "agentbox-doctor"}}),
    ("/v1/messages", {"model": model, "messages": msgs, "max_tokens": 1,
     "extra_headers": {"X-Probe": "agentbox-doctor"}}),
    ("/v1/responses", {"model": model, "input": "x", "api_key": "agentbox-doctor-probe"}),
    ("/chat/completions", {"model": model, "messages": msgs, "max_tokens": 1,
     "headers": {"X-Probe": "agentbox-doctor"}}),
):
    s = call("POST", path, body)
    if s != 400:
        bad.append(f"{path} {sorted(set(body) - {'model', 'messages', 'input', 'max_tokens'})}"
                   f" -> {s} (want 400)")
print(("FAIL 21 router-headers: " + "; ".join(bad)) if bad else
      "PASS 21 router-headers: extra_headers / headers / api_key in the body -> 400")
# residual routes outside allowed_routes that answer anyway: notes, not FAIL,
# unless one yields admin access (a /login session that opens an admin route)
notes, bad = [], []
for m, p in (("GET", "/ui"), ("GET", "/login"), ("GET", "/langfuse/x")):
    notes.append(f"{p} {call(m, p)}")
import urllib.parse
form = urllib.parse.urlencode({"username": "admin", "password": key}).encode()
req = urllib.request.Request("http://router:4000/login", data=form, method="POST",
    headers={"Content-Type": "application/x-www-form-urlencoded"})
cookie = ""
class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None
op2 = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect)
try:
    with op2.open(req, timeout=30) as r:
        st, cookie = r.status, r.headers.get("Set-Cookie") or ""
except urllib.error.HTTPError as e:
    st, cookie = e.code, e.headers.get("Set-Cookie") or ""
except OSError as e:
    st = "error " + type(e).__name__
notes.append(f"POST /login {st}" + (" (sets a cookie)" if cookie else ""))
if cookie:
    tok = cookie.split(";", 1)[0]
    for m, p in admin:
        req = urllib.request.Request("http://router:4000" + p, method=m,
            data=b"{}" if m == "POST" else None,
            headers={"Cookie": tok, "Content-Type": "application/json"})
        try:
            with op.open(req, timeout=30) as r:
                bad.append(f"{m} {p} with the /login cookie -> {r.status}")
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403, 404):
                bad.append(f"{m} {p} with the /login cookie -> {e.code}")
        except OSError:
            pass
print(("FAIL 21 router-residual: " + "; ".join(bad)) if bad else
      "PASS 21 router-residual: no admin action; residual answers: " + ", ".join(notes))
"""

# Router filesystem: the router uid owns no file; its code and the guard are
# not writable by it (the image's files belong to uid 65534, it runs as 10003).
ROUTER_FS = r"""
import os
bad = []
uid = os.getuid()
if uid in (0, 65534):
    bad.append(f"router runs as uid {uid}")
for p in ("/app", "/app/.venv/lib/python3.13/site-packages",
          "/app/.venv/lib/python3.13/site-packages/litellm/__init__.py",
          "/opt/agentbox-router", "/opt/agentbox-router/agentbox_guard.py", "/etc/router"):
    if os.access(p, os.W_OK):
        bad.append(f"writable {p}")
g = os.stat("/opt/agentbox-router/agentbox_guard.py")
if g.st_uid != 0 or g.st_mode & 0o022:
    bad.append("guard not root-owned 0644")
try:
    open("/app/agentbox-doctor-probe", "w").close()
    os.unlink("/app/agentbox-doctor-probe")
    bad.append("created /app/agentbox-doctor-probe")
except OSError:
    pass
print(("FAIL 21 router-fs: " + "; ".join(bad)) if bad else
      f"PASS 21 router-fs: uid {uid}; /app, site-packages, guard not writable")
"""


def _result(status, check, detail=""):
    from .doctor import Result

    return Result(status, check, detail)


def check_13(b: boxmod.Box, ua: str) -> list:
    """13 (router): the gateway probe, run in the router container."""
    from .doctor import parse_lines, pick_denied
    from .doctor_mcp import GW_PROBE, pick_gateway_allowed

    doms = router.egress_domains(b.profile)
    probe = GW_PROBE.replace("13 (mcp-gateway)", "13 (router)")
    args = [ua, pick_gateway_allowed(doms), pick_denied(doms), "", "11434 3128 22 8080"]
    r = boxmod.dc(
        b, "exec", "-T", router.SERVICE, "python3", "-", *args,
        input=probe, check=False, timeout=120,
    )  # fmt: skip
    res = parse_lines(r.stdout)
    return res or [_result("FAIL", "13 (router)", f"no result: {r.stderr.strip()[-300:]}")]


def check_21(b: boxmod.Box) -> list:
    from .doctor import parse_lines

    if not compose.has_router(b.profile):
        why = "no [models.remote.*] in this profile (no router)"
        return [_result("SKIP", "21 router", why)]
    st = boxmod.router_health(b)
    res = [_result("PASS" if st == "healthy" else "FAIL", "21 router-health", f"healthcheck: {st}")]
    model = sorted(b.profile.models.remote)[0]
    r = boxmod.exec_in(
        b, ["python3", "-", model, json.dumps(ADMIN_ROUTES)], input=AGENT_PROBE, timeout=180
    )
    got = parse_lines(r.stdout)
    have = {x.check for x in got}
    fs = boxmod.dc(
        b, "exec", "-T", router.SERVICE, "python3", "-", input=ROUTER_FS, check=False, timeout=60
    )
    res += parse_lines(fs.stdout) or [
        _result("FAIL", "21 router-fs", f"no result: {fs.stderr.strip()[-300:]}")
    ]
    for c in ("21 router-routes", "21 router-api-base", "21 router-headers",
              "21 router-residual"):  # fmt: skip
        if c not in have:
            got.append(_result("FAIL", c, f"no result (exit {r.returncode}): {r.stderr[-300:]}"))
    return res + got
