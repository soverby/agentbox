#!/usr/bin/env python3
"""P6b smoke test (PLAN §5 P6b) against real Docker: OAuth MCP upstreams.

A stub OAuth AS + protected MCP server (tests/integration/p6b_stub.py) runs
in a container with a test CA, as `stub.agentbox-test` (MCP, RFC 9728
metadata) and `auth.agentbox-test` (AS, RFC 8414 metadata, DCR, token,
revoke). As in P5: squid denies private destination IPs, so the stub is on a
harness-only network with a documentation-range subnet (203.0.113.0/24)
that only the egress container joins; the squid config stays the production
render (checked byte for byte). Test-only trust of the stub CA:
- host `mcp login`: AGENTBOX_TEST_OAUTH_CA + AGENTBOX_TEST_OAUTH_CONNECT (the
  stub's port 443 is published on 127.0.0.1 only);
- gateway: the harness appends the CA to the running container's system
  bundle (exec as root); the file is diffed against the image's first.
The stub auto-approves: the smoke plays the browser (`mcp login
--no-browser` prints the URL; the smoke requests it and follows the 302 to
the loopback callback).

Runs the real CLI with AGENTBOX_CONFIG_HOME / AGENTBOX_STATE_HOME in a temp
dir and the `env` secret backend (no keychain). Removes everything it made.

Usage: python3 tests/integration/p6b_smoke.py
"""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it6b-{TAG}"
PROJECT = f"agentbox-{NAME}"
PREFIX = f"agentbox-test-{TAG}"
TESTNET = f"agentbox-p6btest-{TAG}"
TESTNET_SUBNET = "203.0.113.0/24"
STUB_IP = "203.0.113.20"
RS_HOST, AS_HOST = "stub.agentbox-test", "auth.agentbox-test"
STUB_NAME = f"agentbox-p6bstub-{TAG}"
STUB = ROOT / "tests" / "integration" / "p6b_stub.py"
BUNDLE = "/etc/ssl/certs/ca-certificates.crt"
sys.path.insert(0, str(ROOT / "cli"))
from agentbox import box as boxmod  # noqa: E402
from agentbox import images, mcpgw, secretstore  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []

PROFILE = """
[box]
agents = ["claude"]

[[mount]]
host = "{proj}"
mode = "rw"
allow_dotpath = true

[network]
mode = "strict"
presets = ["anthropic"]

[mcp.servers.lin]
url = "https://{rs}/mcp"
auth = "oauth"
tools = ["whoami"]
"""


def rec(ok: bool | None, name: str, detail: str = "") -> bool:
    st = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    RESULTS.append((st, name, detail))
    print(f"{st} {name}" + (f": {detail}" if detail else ""), flush=True)
    return bool(ok)


def sh(args, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(args, capture_output=True, text=True, **kw)


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def sha(v: str) -> str:
    return hashlib.sha256(v.encode()).hexdigest()[:16]


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p6b-"))
        self.vault = Path(tempfile.mkdtemp(prefix="agentbox-p6b-store-"))
        self.work = Path.home() / f".agentbox-it6b-{TAG}"
        self.proj = self.work / "proj"
        self.proj.mkdir(parents=True)
        self.certs = self.roots / "certs"
        self.logs = self.roots / "stublogs"
        self.logs.mkdir()
        os.chmod(self.logs, 0o777)
        self.sport = free_port()
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(f'secret_backend = "env"\nsecret_prefix = "{PREFIX}"\n')
        (cfg / "profiles" / f"{NAME}.toml").write_text(PROFILE.format(proj=self.proj, rs=RS_HOST))
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.vault / "store.json"),
            AGENTBOX_TEST_OAUTH_CA=str(self.certs / "ca.pem"),
            AGENTBOX_TEST_OAUTH_CONNECT=(
                f"{RS_HOST}:443=127.0.0.1:{self.sport},{AS_HOST}:443=127.0.0.1:{self.sport}"
            ),  # fmt: skip
            PYTHONPATH=str(ROOT / "cli"),
        )
        for k in ("AGENTBOX_REPO", "HTTPS_PROXY", "https_proxy"):
            self.env.pop(k, None)

    def ab(self, *args, input=None, timeout=1800) -> subprocess.CompletedProcess:
        return sh([sys.executable, "-m", "agentbox.cli", *args], env=self.env, cwd=str(self.proj),
                  timeout=timeout, input=input,
                  stdin=None if input is not None else subprocess.DEVNULL)  # fmt: skip

    @property
    def state(self) -> Path:
        return self.roots / "state" / NAME

    def compose(self, *args, **kw) -> subprocess.CompletedProcess:
        return sh(["docker", "compose", "-p", PROJECT, "-f", str(self.state / "compose.json"),
                   *args], **kw)  # fmt: skip

    def box(self, script: str, input=None) -> subprocess.CompletedProcess:
        return self.ab("shell", NAME, "--", "sh", "-c", script, input=input, timeout=600)

    def client(self, *args: str) -> dict:
        code = (ROOT / "tests" / "isolation" / "mcp_client.py").read_text()
        r = self.ab("shell", NAME, "--", "python3", "-", *args, input=code, timeout=600)
        try:
            return json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"error": f"exit {r.returncode}: {r.stderr.strip()[-300:]}"}

    def store(self) -> dict:
        f = self.vault / "store.json"
        return json.loads(f.read_text()) if f.is_file() else {}

    def token_key(self) -> str:
        return secretstore._env_var(f"{PREFIX}/{NAME}/_MCP_OAUTH_LIN")

    def stub_events(self, ev: str | None = None) -> list[dict]:
        f = self.logs / "stub.jsonl"
        out = []
        for line in f.read_text().splitlines() if f.is_file() else []:
            try:
                d = json.loads(line)
            except ValueError:
                continue
            if ev is None or d.get("ev") == ev:
                out.append(d)
        return out

    def stub_https(self, method: str, url: str, form: dict | None = None) -> tuple[int, dict]:
        """The smoke as a browser / admin: https to the stub via its host port."""
        u = urlsplit(url)
        ctx = ssl.create_default_context(cafile=str(self.certs / "ca.pem"))
        conn = http.client.HTTPSConnection(u.hostname, 443, context=ctx, timeout=20)
        sock = socket.create_connection(("127.0.0.1", self.sport), 20)
        conn.sock = ctx.wrap_socket(sock, server_hostname=u.hostname)
        from urllib.parse import urlencode

        body = urlencode(form).encode() if form is not None else None
        hdr = {"Content-Type": "application/x-www-form-urlencoded"} if form is not None else {}
        conn.request(method, u.path + (f"?{u.query}" if u.query else ""), body=body, headers=hdr)
        r = conn.getresponse()
        r.read()
        hdrs = {k.lower(): v for k, v in r.getheaders()}
        conn.close()
        return r.status, hdrs

    def gw(self, *argv: str, user: str | None = None, input=None) -> subprocess.CompletedProcess:
        u = ["-u", user] if user else []
        return self.compose("exec", "-T", *u, "mcp-gateway", *argv, input=input)


def make_certs(d: Path) -> None:
    d.mkdir()
    o = ["openssl"]
    sh([*o, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2", "-subj",
        "/CN=agentbox-p6b-test-ca", "-keyout", str(d / "ca.key"), "-out", str(d / "ca.pem"),
        "-addext", "basicConstraints=critical,CA:TRUE", "-addext",
        "keyUsage=critical,keyCertSign,cRLSign"], check=True)  # fmt: skip
    sh([*o, "req", "-newkey", "rsa:2048", "-nodes", "-subj", f"/CN={RS_HOST}",
        "-keyout", str(d / "server.key"), "-out", str(d / "server.csr")], check=True)  # fmt: skip
    (d / "ext.cnf").write_text(
        f"subjectAltName=DNS:{RS_HOST},DNS:{AS_HOST}\nbasicConstraints=CA:FALSE\n"
        "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n"
    )
    sh([*o, "x509", "-req", "-in", str(d / "server.csr"), "-CA", str(d / "ca.pem"),
        "-CAkey", str(d / "ca.key"), "-CAcreateserial", "-days", "2",
        "-extfile", str(d / "ext.cnf"), "-out", str(d / "server.pem")], check=True)  # fmt: skip
    for f in d.iterdir():
        os.chmod(f, 0o644)


def start_stub(e: Env, image: str) -> None:
    r = sh(["docker", "network", "create", "--subnet", TESTNET_SUBNET, TESTNET])
    if r.returncode != 0:
        raise RuntimeError(f"test network: {r.stderr.strip()}")
    r = sh(["docker", "run", "-d", "--name", STUB_NAME, "--network", TESTNET, "--ip", STUB_IP,
            "--network-alias", RS_HOST, "--network-alias", AS_HOST,
            "-p", f"127.0.0.1:{e.sport}:443", "--user", "0", "--entrypoint", "python3",
            "-v", f"{STUB}:/stub.py:ro", "-v", f"{e.certs}:/c:ro", "-v", f"{e.logs}:/logs",
            image, "-u", "/stub.py", "--cert", "/c/server.pem", "--key", "/c/server.key",
            "--log", "/logs/stub.jsonl"])  # fmt: skip
    if r.returncode != 0:
        raise RuntimeError(f"stub: {r.stderr.strip()}")
    for _ in range(60):
        try:
            st, _ = e.stub_https(
                "GET", f"https://{AS_HOST}/.well-known/oauth-authorization-server/as"
            )
            if st == 200:
                return
        except OSError:
            pass
        time.sleep(0.5)
    raise RuntimeError("stub did not answer: " + sh(["docker", "logs", STUB_NAME]).stderr[-500:])


def container_ids() -> dict[str, str]:
    out = sh(["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
              "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}']).stdout  # fmt: skip
    return dict(line.split() for line in out.splitlines() if line.strip())


def connect_egress() -> None:
    cid = container_ids()["egress"]
    r = sh(["docker", "network", "connect", TESTNET, cid])
    if r.returncode != 0 and "already exists" not in r.stderr:
        raise RuntimeError(f"connect egress: {r.stderr.strip()}")


def trust_ca_in_gateway(e: Env, image: str) -> tuple[bool, str]:
    """Test-only: append the stub CA to the running gateway's system bundle.
    Before: the container's bundle must equal the image's (production)."""
    prod = sh(["docker", "run", "--rm", "--entrypoint", "sha256sum", image, BUNDLE]).stdout.split()
    live = e.gw("sha256sum", BUNDLE).stdout.split()
    if not prod or prod[:1] != live[:1]:
        return False, f"bundle differs from the image before the override: {prod} {live}"
    ca = (e.certs / "ca.pem").read_text()
    r = e.gw("sh", "-c", f"cat >> {BUNDLE}", user="0", input=ca)
    if r.returncode != 0:
        return False, r.stderr.strip()[-300:]
    after = e.gw("cat", BUNDLE).stdout
    base = sh(["docker", "run", "--rm", "--entrypoint", "cat", image, BUNDLE]).stdout
    return after == base + ca, "container bundle == image bundle + test CA"


def playwright_login(e: Env, extra: list[str] | None = None, idle: bool = False):
    """`mcp login --no-browser`, playing the browser from the printed URL."""
    p = subprocess.Popen(
        [sys.executable, "-m", "agentbox.cli", "mcp", "login", NAME, "lin", "--no-browser",
         "--timeout", "60", *(extra or [])],
        env=e.env, cwd=str(e.proj), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        stdin=subprocess.DEVNULL,
    )  # fmt: skip
    lines: list[str] = []
    url = None
    assert p.stdout is not None
    for line in p.stdout:
        lines.append(line)
        if line.strip().startswith(f"https://{AS_HOST}/as/authorize?"):
            url = line.strip()
            break
    if url is None:
        p.wait(30)
        return p.returncode, "".join(lines), p.stderr.read() if p.stderr else ""
    held = []
    if idle:  # idle TCP connections to the loopback port must not block the callback
        from urllib.parse import parse_qs

        cbport = urlsplit(parse_qs(urlsplit(url).query)["redirect_uri"][0]).port
        held = [socket.create_connection(("127.0.0.1", cbport)) for _ in range(2)]
        held[1].sendall(b"GET /callback?code=")  # partial request, then silence
    e.login_t0 = time.monotonic()
    st, hdrs = e.stub_https("GET", url)
    loc = hdrs.get("location", "")
    cb = {"status": st, "location_ok": loc.startswith("http://127.0.0.1:")}
    if cb["location_ok"]:
        import urllib.request

        with urllib.request.urlopen(loc, timeout=20) as r:
            cb["callback"] = r.status
    rest, err = p.communicate(timeout=120)
    e.login_dt = time.monotonic() - e.login_t0
    for h in held:
        h.close()
    e.last_login = {"url": url, **cb}
    return p.returncode, "".join(lines) + rest, err


def token_values(e: Env) -> dict[str, str]:
    """Every token the smoke can see: backend set + the gateway's volume copy."""
    out = {}
    raw = e.store().get(e.token_key())
    if raw:
        ts = json.loads(raw)
        for k in ("access_token", "refresh_token", "client_secret"):
            if ts.get(k):
                out[f"backend {k}"] = ts[k]
    r = e.gw("cat", f"{mcpgw.OAUTH_DIR}/lin.json")
    if r.returncode == 0 and r.stdout.strip():
        ts = json.loads(r.stdout)
        for k in ("access_token", "refresh_token", "client_secret"):
            if ts.get(k):
                out[f"volume {k}"] = ts[k]
    return out


def audit(e: Env, markers: dict[str, str], tag: str) -> None:
    hits: list[str] = []

    def scan(where: str, data: str | bytes) -> None:
        b = data.encode() if isinstance(data, str) else data
        hits.extend(f"{n} in {where}" for n, v in markers.items() if v.encode() in b)

    for f in sorted(e.state.rglob("*")):
        if f.is_file():
            scan(f"state:{f.relative_to(e.state)}", f.read_bytes())
    for svc, cid in container_ids().items():
        scan(f"docker inspect {svc}", sh(["docker", "inspect", cid]).stdout)
    scan("docker compose config", e.compose("config").stdout)
    scan("docker compose logs", e.compose("logs", "--no-color").stdout)
    scan(
        "gateway logs dir",
        "".join(
            p.read_text(errors="replace") for p in (e.state / "logs").rglob("*") if p.is_file()
        ),
    )
    r = e.box("env; cat /run/secrets/* 2>/dev/null; ls -la /run/secrets; ps -eww -o args; "
              f"ls -d {mcpgw.OAUTH_DIR} 2>&1")  # fmt: skip
    scan("agent env + /run/secrets + ps", r.stdout)
    if "_MCP_OAUTH" in r.stdout:
        hits.append("agent /run/secrets lists _MCP_OAUTH_*")
    r = e.box(
        "grep -rl -F -f - ~ /tmp 2>/dev/null || true", input="\n".join(markers.values()) + "\n"
    )
    if r.stdout.strip():
        hits.append(f"markers in agent files: {' '.join(r.stdout.split())[:200]}")
    rec(bool(markers) and not hits,
        f"leak audit ({tag}): {len(markers)} OAuth values not in agent (env, /run/secrets, home, "
        "ps), state, logs, compose config, docker inspect", "; ".join(hits))  # fmt: skip


def doctor(e: Env) -> dict[str, tuple[str, str]]:
    r = e.ab("doctor", NAME, timeout=1800)
    res = {}
    for line in r.stdout.splitlines():
        for st in ("PASS", "FAIL", "SKIP", "WARN"):
            if line.startswith(st + " "):
                check, _, detail = line[len(st) + 1 :].partition(": ")
                res[check.strip()] = (st, detail)
    return res


def main() -> int:  # noqa: C901 (linear scenario)
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    e = Env()
    print(f"== roots {e.roots}, stub port {e.sport}", flush=True)
    image = ""
    try:
        make_certs(e.certs)
        image = images.ensure_sidecar(ROOT, mcpgw.SERVICE)
        start_stub(e, image)

        # -- before login
        r = e.ab("mcp", "status", NAME)
        rec(r.returncode == 1 and "lin: needs login (not logged in" in r.stdout,
            "mcp status before login: needs login", r.stdout.strip()[:200])  # fmt: skip
        r = e.ab("secret", "set", NAME, "_MCP_OAUTH_LIN", "--stdin", input="x\n")
        rec(
            r.returncode != 0 and "reserved" in r.stderr,
            "_MCP_OAUTH_* is reserved for `mcp login` (secret set refused)",
            r.stderr.strip(),
        )

        # -- login on the host (DCR, PKCE, resource, loopback, state, iss)
        rc, out, err = playwright_login(e)
        rec(rc == 0 and "lin: logged in" in out, "mcp login completes (--no-browser, smoke plays "
            "the browser)", " ".join((out + err).split())[-400:])  # fmt: skip
        lg = getattr(e, "last_login", {})
        rec(
            lg.get("status") == 302 and lg.get("location_ok") and lg.get("callback") == 200,
            "authorize -> 302 to http://127.0.0.1:<port>/callback -> loopback 200",
            str(lg),
        )
        reg = e.stub_events("register")
        au = e.stub_events("authorize")
        tok = e.stub_events("token")
        rec(
            len(reg) == 1
            and reg[0]["application_type"] == "native"
            and reg[0]["redirect_uris"][0].startswith("http://127.0.0.1:")
            and reg[0]["redirect_uris"][0].endswith("/callback")
            and "refresh_token" in reg[0]["grant_types"],
            "DCR (RFC 7591): native, loopback redirect, refresh_token grant",
            str(reg)[:300],
        )
        rec(len(au) == 1 and au[0]["ok"] and au[0]["method"] == "S256"
            and au[0]["resource"] == f"https://{RS_HOST}/mcp" and au[0]["has_state"]
            and au[0]["scope"] == "mcp:tools offline_access",
            "authorize: PKCE S256, resource (RFC 8707), state, scope from the 401 challenge "
            "+ offline_access", str(au)[:300])  # fmt: skip
        rec(
            len(tok) == 1
            and tok[0]["grant"] == "authorization_code"
            and tok[0]["ok"]
            and tok[0]["pkce"]
            and tok[0]["resource"] == f"https://{RS_HOST}/mcp",
            "token: authorization_code + code_verifier + resource accepted",
            str(tok)[:300],
        )
        raw = e.store().get(e.token_key())
        ts = json.loads(raw) if raw else {}
        rec(ts.get("v") == 1 and ts.get("access_token") and ts.get("refresh_token")
            and ts.get("client_secret") and ts.get("token_endpoint") == f"https://{AS_HOST}/as/token"
            and ts.get("auth_method") == "client_secret_post",
            "token set in the backend (profile scope, env backend in tests)",
            f"key {e.token_key()} keys {sorted(ts)}")  # fmt: skip
        hosts = json.loads((e.state / mcpgw.OAUTH_HOSTS_FILE).read_text())
        rec(
            hosts.get("lin", {}).get("hosts") == [AS_HOST],
            "state records only the token endpoint host (no token)",
            json.dumps(hosts),
        )
        initial = {f"login {k}": ts[k] for k in ("access_token", "refresh_token", "client_secret")}

        # -- up: token set to the gateway only; token host on the gateway allowlist
        r = e.ab("up", NAME)
        rec(r.returncode == 0, "up", " ".join(r.stderr.split())[-300:])
        os.environ.update({k: e.env[k] for k in ("AGENTBOX_CONFIG_HOME", "AGENTBOX_STATE_HOME")})
        b = boxmod.load(NAME)
        ctx = boxmod.ctx_for(b, b.subnet_index())
        rec(
            boxmod.read_conf(ctx.conf_dir) == boxmod.render_egress(b, ctx),
            "squid config on disk == production render (no test override)",
        )
        gwallow = (ctx.conf_dir / "mcp-gateway.allow").read_text().split()
        agallow = (ctx.conf_dir / "agent.allow").read_text().split()
        rec(gwallow == [AS_HOST, RS_HOST] and AS_HOST not in agallow and RS_HOST not in agallow,
            "gateway allowlist = MCP host + token endpoint host; agent allowlist has neither",
            f"gateway {gwallow}")  # fmt: skip
        doc = json.loads((e.state / "compose.json").read_text())
        gsec = [x["source"] for x in doc["services"]["mcp-gateway"].get("secrets", [])]
        asec = [x["source"] for x in doc["services"]["agent"].get("secrets", [])]
        rec(
            "_MCP_OAUTH_LIN" in gsec and "_MCP_OAUTH_LIN" not in asec,
            "compose: _MCP_OAUTH_LIN targets mcp-gateway only",
            f"gw {gsec} agent {asec}",
        )
        connect_egress()
        ok, why = trust_ca_in_gateway(e, image)
        rec(ok, "harness: gateway trusts the test CA (bundle diffed against the image)", why)
        st = {}
        for _ in range(40):  # squid caches the failed lookup before the network join
            st = boxmod.gateway_status(b).get("servers", {}).get("lin", {})
            if st.get("state") == "connected":
                break
            time.sleep(3)
        rec(st.get("state") == "connected", "gateway probe: lin connected", json.dumps(st))

        # -- the agent sees and calls the OAuth server's allowlisted tool
        out = e.client("list")
        rec(
            out.get("tools") == ["lin_whoami"],
            "agent tools/list = [lin_whoami] (allowlist)",
            json.dumps(out)[:300],
        )
        res = e.client("call", "lin_whoami", "{}")
        rec(
            bool(res.get("ok")) and "OAUTH-OK" in res.get("text", ""),
            "agent calls lin_whoami",
            json.dumps(res)[:200],
        )
        res = e.client("probe", "{}", "lin_secret_tool")
        rec(
            not res.get("calls", {}).get("lin_secret_tool", {}).get("ok"),
            "non-allowlisted lin_secret_tool rejected",
            json.dumps(res)[:200],
        )
        gw_token = json.loads((e.state / "box-tokens.json").read_text())["MCP_GATEWAY_TOKEN"]
        mcp_auth = {x["auth"] for x in e.stub_events("mcp") if x["ok"]}
        tools = e.stub_events("tool")
        rec(mcp_auth == {sha(ts["access_token"])}
            and sha(gw_token) not in {x["auth"] for x in e.stub_events("mcp")}
            and [x["tool"] for x in tools] == ["whoami"] and not tools[0]["agent_header"],
            "upstream saw the login access token, never the gateway token or agent headers",
            f"auth {sorted(mcp_auth)} tools {[x['tool'] for x in tools]}")  # fmt: skip

        # -- forced expiry: 401 -> refresh (rotation kept in the volume) -> call works
        e.stub_https("POST", f"https://{AS_HOST}/admin/expire")
        res = e.client("call", "lin_whoami", "{}")
        grants = [x for x in e.stub_events("token") if x["grant"] == "refresh_token"]
        rec(bool(res.get("ok")) and "OAUTH-OK" in res.get("text", "") and len(grants) == 1
            and grants[0]["ok"] and grants[0]["resource"] == f"https://{RS_HOST}/mcp",
            "access token expired at the stub: gateway refreshes (refresh grant + resource) and "
            "the call still works", f"{json.dumps(res)[:120]} grants {grants}")  # fmt: skip
        vol = json.loads(e.gw("cat", f"{mcpgw.OAUTH_DIR}/lin.json").stdout or "{}")
        rec(
            vol.get("refresh_token")
            and vol["refresh_token"] != ts["refresh_token"]
            and vol.get("refreshes") == 1,
            "rotated refresh token kept in the gateway volume",
            f"refreshes {vol.get('refreshes')}",
        )
        r = e.gw("sh", "-c", f"stat -c '%u %a' {mcpgw.OAUTH_DIR} {mcpgw.OAUTH_DIR}/lin.json")
        rec(
            r.stdout.split() == ["10002", "700", "10002", "600"],
            "volume dir 0700 / file 0600, gateway uid",
            r.stdout.strip(),
        )
        r = e.ab("mcp", "status", NAME)
        rec(r.returncode == 0 and "lin: logged in" in r.stdout and "refresh OK" in r.stdout
            and "connected" in r.stdout, "mcp status: logged in, expiry, refresh OK",
            r.stdout.strip()[:300])  # fmt: skip
        # a gateway restart reuses the rotated token (not the spent login refresh token)
        e.compose("restart", "mcp-gateway")
        ok, why = trust_ca_in_gateway(e, image)  # restart keeps the container fs; check anyway
        e.stub_https("POST", f"https://{AS_HOST}/admin/expire")
        res = e.client("call", "lin_whoami", "{}")
        grants = [x for x in e.stub_events("token") if x["grant"] == "refresh_token"]
        rec(bool(res.get("ok")) and len(grants) == 2 and all(g["ok"] for g in grants),
            "after a gateway restart: refresh with the rotated token works",
            f"{json.dumps(res)[:120]} grants {grants}")  # fmt: skip

        markers = {**initial, **token_values(e)}
        audit(e, markers, "after login + refresh")

        # -- doctor with a healthy OAuth upstream
        res = doctor(e)
        for c in ("20 upstreams", "20 oauth-store", "20 gateway-fs", "20 auth", "20 policy",
                  "20 upstream-direct"):  # fmt: skip
            s, d = res.get(c, ("-", "missing"))
            rec(s == "PASS", f"doctor {c}", d[:200])

        # -- the AS revokes everything: needs re-login everywhere
        e.stub_https("POST", f"https://{AS_HOST}/admin/revoke")
        res = e.client("call", "lin_whoami", "{}")
        rec(not res.get("ok"), "after revocation the call fails", json.dumps(res)[:200])
        markers.update(token_values(e))
        stf = e.state / "logs" / "mcp" / "status.json"
        sj = json.loads(stf.read_text()).get("servers", {}).get("lin", {})
        want = f"re-login needed (agentbox mcp login {NAME} lin)"
        rec(
            sj == {"state": "failed", "reason": want},
            "status.json: lin failed: re-login needed",
            json.dumps(sj),
        )
        res = doctor(e)
        s, d = res.get("20 upstreams", ("-", "missing"))
        rec(s == "FAIL" and f"lin ({want})" in d, "doctor 20 upstreams FAILs naming lin", d[:240])
        r = e.ab("mcp", "status", NAME)
        rec(
            r.returncode == 1 and f"lin: needs login (agentbox mcp login {NAME} lin)" in r.stdout,
            "mcp status: needs login",
            r.stdout.strip()[:300],
        )
        n_grants = len(e.stub_events("token"))
        e.client("call", "lin_whoami", "{}")
        rec(len(e.stub_events("token")) == n_grants, "no refresh retries after a refused refresh")
        audit(e, markers, "after revocation")

        # -- logout: backend item + volume copy removed, revocation attempted
        n_rev = len(e.stub_events("revoke"))
        r = e.ab("mcp", "logout", NAME, "lin")
        rec(r.returncode == 0 and e.token_key() not in e.store()
            and "volume copy removed" in r.stdout,
            "mcp logout: backend item deleted, gateway volume copy removed",
            " ".join((r.stdout + r.stderr).split())[-300:])  # fmt: skip
        rec(
            len(e.stub_events("revoke")) > n_rev,
            "logout tried RFC 7009 revocation",
            str(e.stub_events("revoke")[n_rev:])[:200],
        )
        r = e.gw("sh", "-c", f"ls -A {mcpgw.OAUTH_DIR}")
        rec(
            r.returncode == 0 and "lin.json" not in r.stdout,
            "volume has no lin.json after logout",
            r.stdout.strip(),
        )
        hosts = json.loads((e.state / mcpgw.OAUTH_HOSTS_FILE).read_text())
        rec("lin" not in hosts, "logout drops the endpoint hosts from state", json.dumps(hosts))
        r = e.gw("sh", "-c", "ls /run/secrets")
        rec(
            "_MCP_OAUTH_LIN" not in r.stdout,
            "after logout the gateway was recreated without it",
            r.stdout.strip(),
        )
        audit(e, markers, "after logout")

        # -- box-down logout revokes the CURRENT (rotated) tokens, not the stale
        # backend copy; login survives idle connections on the loopback port
        rc, out, err = playwright_login(e, idle=True)
        rec(rc == 0 and "lin: logged in" in out and e.login_dt < 20,
            "re-login with 2 idle/partial connections held on the loopback port",
            f"{e.login_dt:.1f}s " + " ".join((out + err).split())[-200:])  # fmt: skip
        ok, why = trust_ca_in_gateway(e, image)  # login re-applied `up`: gateway recreated
        for _ in range(40):
            if boxmod.gateway_status(b).get("servers", {}).get("lin", {}).get("state") == (
                "connected"
            ):
                break
            time.sleep(3)
        e.stub_https("POST", f"https://{AS_HOST}/admin/expire")
        res = e.client("call", "lin_whoami", "{}")
        backend = json.loads(e.store()[e.token_key()])
        vol = json.loads(e.gw("cat", f"{mcpgw.OAUTH_DIR}/lin.json").stdout or "{}")
        rec(bool(res.get("ok")) and vol.get("refresh_token")
            and vol["refresh_token"] != backend["refresh_token"],
            "after refresh the volume refresh token differs from the backend copy",
            json.dumps(res)[:120])  # fmt: skip
        markers.update(token_values(e))
        r = e.ab("down", NAME)
        rec(r.returncode == 0, "down (box stopped, volume kept)")
        n_rev = len(e.stub_events("revoke"))
        r = e.ab("mcp", "logout", NAME, "lin")
        revs = e.stub_events("revoke")[n_rev:]
        rec(r.returncode == 0 and "revocation: ok" in r.stdout and "WARNING" not in r.stdout
            and "volume copy removed" in r.stdout
            and [(x["hint"], x["known"], x["ok"]) for x in revs]
            == [("refresh_token", True, True), ("access_token", True, True)],
            "box-down logout: revokes the current rotated refresh + access token (stub knew "
            "both), removes the volume copy", " ".join(r.stdout.split())[-250:]
            + f" revs {revs}")  # fmt: skip
        st, _ = e.stub_https(
            "POST",
            f"https://{AS_HOST}/as/token",
            {
                "grant_type": "refresh_token",
                "refresh_token": vol["refresh_token"],
                "client_id": backend["client_id"],
                "client_secret": backend["client_secret"],
            },
        )
        rec(st == 400, "the rotated refresh token no longer works after logout", f"HTTP {st}")
        r = sh(["docker", "run", "--rm", "-v", f"{mcpgw.oauth_volume(NAME)}:/v", "--entrypoint",
                "ls", image, "-A", "/v"])  # fmt: skip
        rec(
            r.returncode == 0 and "lin.json" not in r.stdout,
            "volume has no lin.json after box-down logout",
            r.stdout.strip(),
        )
        rec(e.token_key() not in e.store(), "backend item deleted (box-down logout)")
        audit_files = e.state
        hits = [
            n
            for n, v in markers.items()
            for f in audit_files.rglob("*")
            if f.is_file() and v.encode() in f.read_bytes()
        ]
        rec(not hits, "state dir holds no OAuth value after box-down logout", str(hits))
    except Exception as ex:  # noqa: BLE001
        import traceback

        traceback.print_exc()
        rec(False, "smoke harness", repr(ex))
    finally:
        cleanup(e, before_vols)
    return finish()


def cleanup(e: Env, before_vols: set[str]) -> None:
    f = e.state / "compose.json"
    if f.exists():
        sh(["docker", "compose", "-p", PROJECT, "-f", str(f), "down", "-v", "--remove-orphans",
            "--timeout", "2"])  # fmt: skip
    sh(["docker", "rm", "-f", STUB_NAME])
    sh(["docker", "network", "rm", TESTNET])
    for v in (f"{PROJECT}-home", mcpgw.oauth_volume(NAME)):
        sh(["docker", "volume", "rm", "-f", v])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    shutil.rmtree(e.vault, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if TAG in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    rec(
        not ours and not new_vols and not any(p.exists() for p in (e.work, e.roots, e.vault)),
        "cleanup (containers, networks, volumes, dirs)",
        f"leftovers {ours} {new_vols}",
    )


def finish() -> int:
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
          f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip")  # fmt: skip
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
