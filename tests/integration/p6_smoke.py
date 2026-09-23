#!/usr/bin/env python3
"""P6 smoke test (PLAN §5 P6) against real Docker: the MCP gateway.

Upstreams:
- hostsrv: streamable HTTP stub on host 127.0.0.1 (http://host.docker.internal:<p>/mcp),
  bearer checked by the stub (tools allowed_a, allowed_b, forbidden).
- ssesrv: the same stub over SSE (http://host.docker.internal:<p>/sse), own bearer.
- local: stdio server run inside the gateway (python3 -c …).
- time: stdio server via `uvx` (PyPI through the gateway's egress allowlist).
- deepwiki: a real remote server (https://mcp.deepwiki.com/mcp, no auth) reached
  by CONNECT through squid. A stub on a Docker network cannot be the remote
  case: squid denies private destination IPs for every client (§2.2).

Runs the real CLI with AGENTBOX_CONFIG_HOME / AGENTBOX_STATE_HOME in a temp
dir and the `env` secret backend (no keychain). Removes everything it made.

Usage: python3 tests/integration/p6_smoke.py
"""

from __future__ import annotations

import json
import os
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
TAG = secrets.token_hex(3)
NAME = f"it6-{TAG}"
PROJECT = f"agentbox-{NAME}"
PREFIX = f"agentbox-test-{TAG}"
LOCK = ROOT / "images" / "mcp-gateway" / "requirements.lock"
sys.path.insert(0, str(ROOT / "cli"))
from agentbox.launch import CODEX_MCP_OVERRIDES  # noqa: E402

RESULTS: list[tuple[str, str, str]] = []

STDIO_CODE = (
    "import os\n"
    "from fastmcp import FastMCP\n"
    "m = FastMCP('local')\n"
    "@m.tool\n"
    "def ping() -> str:\n"
    "    bad = [k for k in os.environ if 'TOK' in k or k.startswith('AGENTBOX')]\n"
    "    return 'env-clean' if not bad else 'env-leak:' + ','.join(bad)\n"
    "@m.tool\n"
    "def forbidden_local() -> str:\n"
    "    return 'FORBIDDEN-LOCAL-RAN'\n"
    "m.run(show_banner=False)\n"
)

PROFILE = """
[box]
agents = ["claude", "codex", "pi"]

[[mount]]
host = "{proj}"
mode = "rw"
allow_dotpath = true

[network]
mode = "strict"
presets = ["anthropic", "openai", "github"]

[secrets]
HOST_MCP_TOK = {{}}
SSE_MCP_TOK = {{}}

[mcp.servers.hostsrv]
url = "http://host.docker.internal:{hport}/mcp"
bearer = "HOST_MCP_TOK"
tools = ["allowed_a", "allowed_b"]

[mcp.servers.ssesrv]
url = "http://host.docker.internal:{sport}/sse"
bearer = "SSE_MCP_TOK"
tools = ["allowed_a"]

[mcp.servers.local]
command = ["python3", "-c", {code}]
tools = ["ping"]

[mcp.servers.time]
command = ["uvx", "mcp-server-time==2026.8.18"]
tools = ["get_current_time"]

[mcp.servers.mem]
command = ["npx", "-y", "@modelcontextprotocol/server-memory@2026.8.31"]
tools = ["read_graph"]

[mcp.servers.dead]
url = "http://host.docker.internal:{dport}/mcp"

[mcp.servers.evil]
url = "http://host.docker.internal:{eport}/mcp"
"""
# The reviewer's terminal-escape payload (OSC title, clear screen, colour) + C1 CSI.
ESC_PAYLOAD = "\x1b]0;PWNED\x07\x1b[2J\x1b[31mFAKE\x1b[0m \x9b31m"


def start_evil(port: int):
    """Host HTTP 'MCP server' whose every JSON-RPC answer is an error carrying
    ESC_PAYLOAD: the gateway's failure reason then holds upstream-chosen text."""
    import http.server
    import threading

    class H(http.server.BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            n = int(self.headers.get("Content-Length") or 0)
            try:
                rid = json.loads(self.rfile.read(n)).get("id", 0)
            except ValueError:
                rid = 0
            err = {"code": -32000, "message": ESC_PAYLOAD}
            body = json.dumps({"jsonrpc": "2.0", "id": rid, "error": err}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", port), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


DEEPWIKI_TOML = """
[mcp.servers.deepwiki]
url = "https://mcp.deepwiki.com/mcp"
tools = ["read_wiki_structure"]
"""


def host_reaches_deepwiki() -> tuple[bool, str]:
    """The remote-style case needs the public DeepWiki server; if the host
    itself cannot reach it, that case is SKIP (not FAIL)."""
    import urllib.error
    import urllib.request

    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-06-18", "capabilities": {},
        "clientInfo": {"name": "p6", "version": "1"}}}).encode()  # fmt: skip
    hdr = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
    req = urllib.request.Request("https://mcp.deepwiki.com/mcp", body, hdr, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status == 200, f"HTTP {r.status}"
    except (OSError, urllib.error.URLError) as ex:
        return False, repr(ex)[:200]


DEEPWIKI, DEEPWIKI_WHY = host_reaches_deepwiki()

ADAPTER = "/usr/local/lib/agentbox/pi-mcp-adapter/node_modules/pi-mcp-adapter/dist"
PI_PROBE = f"""
import {{ loadMcpConfig }} from "{ADAPTER}/config.js";
import {{ McpServerManager }} from "{ADAPTER}/server-manager.js";
// The same load the wrapper sets up: --mcp-config + PI_MCP_CONFIG_MODE=exclusive.
const cfg = loadMcpConfig("/etc/agentbox/pi-mcp.json", process.cwd());
console.log("PI-SERVERS " + Object.keys(cfg.mcpServers).join(","));
const m = new McpServerManager(process.cwd());
const c = await m.connect("agentbox", cfg.mcpServers.agentbox);
console.log("PI-TOOLS " + c.tools.map((t) => t.name).sort().join(","));
process.exit(0);
"""
WANT_TOOLS = [
    *(["deepwiki_read_wiki_structure"] if DEEPWIKI else []),
    "hostsrv_allowed_a",
    "hostsrv_allowed_b",
    "local_ping",
    "mem_read_graph",
    "ssesrv_allowed_a",
    "time_get_current_time",
]
PI_WANT = "PI-TOOLS " + ",".join(WANT_TOOLS)

DENY_CALLS = [
    "hostsrv_forbidden",
    "ssesrv_allowed_b",
    "ssesrv_forbidden",
    "local_forbidden_local",
    *(["deepwiki_ask_wiki_question"] if DEEPWIKI else []),
    "mem_delete_entities",
    "dead_anything",
    "evil_anything",
    "time_convert_time",
    "forbidden",
    "allowed_a",
    "nosuch_tool",
]


def marker(label: str) -> str:
    return f"MARK{TAG}{label}{secrets.token_hex(12)}"


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


class Env:
    def __init__(self) -> None:
        self.roots = Path(tempfile.mkdtemp(prefix="agentbox-p6-"))
        self.vault = Path(tempfile.mkdtemp(prefix="agentbox-p6-store-"))
        self.work = Path.home() / f".agentbox-it6-{TAG}"
        self.proj = self.work / "proj"
        self.proj.mkdir(parents=True)
        self.hport, self.sport, self.dport = free_port(), free_port(), free_port()
        self.eport = free_port()
        self.stub_log = self.roots / "stub-calls.log"
        self.stub_log.touch()
        cfg = self.roots / "config"
        (cfg / "profiles").mkdir(parents=True)
        (cfg / "config.toml").write_text(f'secret_backend = "env"\nsecret_prefix = "{PREFIX}"\n')
        (cfg / "profiles" / f"{NAME}.toml").write_text(
            PROFILE.format(
                proj=self.proj,
                hport=self.hport,
                sport=self.sport,
                dport=self.dport,
                eport=self.eport,
                code=json.dumps(f"exec({STDIO_CODE!r})"),
            )
            + (DEEPWIKI_TOML if DEEPWIKI else "")  # fmt: skip
        )
        self.env = dict(
            os.environ,
            AGENTBOX_CONFIG_HOME=str(cfg),
            AGENTBOX_STATE_HOME=str(self.roots / "state"),
            AGENTBOX_TEST_SECRET_STORE=str(self.vault / "store.json"),
            PYTHONPATH=str(ROOT / "cli"),
        )
        self.env.pop("AGENTBOX_REPO", None)
        self.stubs: list[subprocess.Popen] = []

    def ab(self, *args, input=None, timeout=1800) -> subprocess.CompletedProcess:
        return sh(
            [sys.executable, "-m", "agentbox.cli", *args],
            env=self.env, cwd=str(self.proj), timeout=timeout, input=input,
            stdin=None if input is not None else subprocess.DEVNULL,
        )  # fmt: skip

    @property
    def state(self) -> Path:
        return self.roots / "state" / NAME

    def compose(self, *args) -> subprocess.CompletedProcess:
        return sh(["docker", "compose", "-p", PROJECT, "-f", str(self.state / "compose.json"),
                   *args])  # fmt: skip

    def box(self, script: str, input=None) -> subprocess.CompletedProcess:
        return self.ab("shell", NAME, "--", "sh", "-c", script, input=input, timeout=600)

    def client(self, *args: str) -> dict:
        """tests/isolation/mcp_client.py in the agent (stdin), as the doctor runs it."""
        code = (ROOT / "tests" / "isolation" / "mcp_client.py").read_text()
        r = self.ab("shell", NAME, "--", "python3", "-", *args, input=code, timeout=600)
        try:
            return json.loads(r.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            return {"error": f"exit {r.returncode}: {r.stderr.strip()[-300:]}"}

    def start_stub(self, transport: str, port: int, bearer: str) -> None:
        p = subprocess.Popen(
            ["uv", "run", "--no-project", "-q", "--python", "3.13", "--with-requirements",
             str(LOCK), "python", str(ROOT / "tests/integration/p6_stub.py"), transport,
             str(port), str(self.stub_log)],
            env=dict(os.environ, STUB_BEARER=bearer), stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL,
        )  # fmt: skip
        self.stubs.append(p)
        for _ in range(120):
            try:
                socket.create_connection(("127.0.0.1", port), timeout=1).close()
                return
            except OSError:
                time.sleep(0.5)
        raise RuntimeError(f"stub {transport} did not start on {port}")


def ips_agent(e) -> str:
    doc = json.loads((e.state / "compose.json").read_text())
    return doc["services"]["agent"]["networks"]["internal"]["ipv4_address"]


def container_ids() -> dict[str, str]:
    out = sh(
        ["docker", "ps", "-a", "--filter", f"label=com.docker.compose.project={PROJECT}",
         "--format", '{{.Label "com.docker.compose.service"}} {{.ID}}']
    ).stdout  # fmt: skip
    return dict(line.split() for line in out.splitlines() if line.strip())


def doctor(e: Env) -> dict[str, tuple[str, str]]:
    r = e.ab("doctor", NAME, timeout=1800)
    e.last_doctor = r.stdout + r.stderr
    res = {}
    for line in r.stdout.splitlines():
        for st in ("PASS", "FAIL", "SKIP", "WARN"):
            if line.startswith(st + " "):
                check, _, detail = line[len(st) + 1 :].partition(": ")
                res[check.strip()] = (st, detail)
    return res


def stub_direct_code(port: int, path: str, method: str = "POST") -> int:
    """Host-side negative control: the stub refuses a request without the bearer."""
    import urllib.error
    import urllib.request

    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}", data=b"{}" if method == "POST" else None,
        method=method,
        headers={"Content-Type": "application/json",
                 "Accept": "application/json, text/event-stream"},
    )  # fmt: skip
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as ex:
        return ex.code


def audit(e: Env, markers: dict[str, str], tag: str) -> None:
    """Upstream bearers: only in the gateway's /run/secrets (by design)."""
    hits: list[str] = []

    def scan(where: str, data: str | bytes) -> None:
        b = data.encode() if isinstance(data, str) else data
        hits.extend(f"{n} in {where}" for n, v in markers.items() if v.encode() in b)

    for f in sorted(e.state.rglob("*")):
        if f.is_file():
            scan(f"state:{f.relative_to(e.state)}", f.read_bytes())
    ids = container_ids()
    for svc, cid in ids.items():
        scan(f"docker inspect {svc}", sh(["docker", "inspect", cid]).stdout)
    scan("docker compose config", e.compose("config").stdout)
    scan("docker compose logs", e.compose("logs", "--no-color").stdout)
    r = e.box("env; cat /run/secrets/* 2>/dev/null; cat ~/.codex/config.toml ~/.pi/agent/mcp.json "
              "2>/dev/null; ps -eww -o args")  # fmt: skip
    scan("agent env + /run/secrets + client configs + ps", r.stdout)
    r = e.box("grep -rl -F -f - ~ 2>/dev/null || true", input="\n".join(markers.values()) + "\n")
    if r.stdout.strip():
        hits.append(f"markers in agent home files: {' '.join(r.stdout.split())[:200]}")
    rec(not hits, f"leak audit ({tag}): upstream bearers not in agent, state, logs, inspect",
        "; ".join(hits))  # fmt: skip


def main() -> int:  # noqa: C901 (linear scenario)
    before_vols = set(sh(["docker", "volume", "ls", "-q"]).stdout.split())
    e = Env()
    print(f"== roots {e.roots}, work {e.work}, stub ports {e.hport} {e.sport}", flush=True)
    bearers = {"HOST_MCP_TOK": marker("host"), "SSE_MCP_TOK": marker("sse")}
    argmark = marker("arg")
    try:
        e.start_stub("http", e.hport, bearers["HOST_MCP_TOK"])
        e.start_stub("sse", e.sport, bearers["SSE_MCP_TOK"])
        e.evil = start_evil(e.eport)
        codes = (stub_direct_code(e.hport, "/mcp"), stub_direct_code(e.sport, "/sse", "GET"))
        rec(codes == (401, 401), "stubs refuse requests without the bearer (control)", str(codes))
        for n, v in bearers.items():
            r = e.ab("secret", "set", NAME, n, "--stdin", input=v + "\n")
            if r.returncode != 0:
                rec(False, f"secret set {n}", r.stderr.strip())

        # -- a user's own Codex / Pi settings exist before the first up
        t0 = time.time()
        r = e.ab("up", NAME)
        rec(r.returncode == 0, "up (gateway included)", f"{time.time() - t0:.1f}s "
            + " ".join(r.stderr.split())[-300:])  # fmt: skip
        warns = [x for x in r.stderr.splitlines() if "is not reachable from mcp-gateway" in x]
        rec(len(warns) == 2 and "MCP server dead " in warns[0] and "MCP server evil " in warns[1],
            "up warns once per failed upstream (only `dead`, `evil`)",
            " | ".join(warns)[:300])  # fmt: skip
        rec("PWNED" in r.stderr and not any(c in r.stderr for c in "\x1b\x07\x9b")
            and "\\x1b]0;PWNED" in r.stderr,
            "hostile upstream error text reaches the terminal escaped (no ESC/BEL/C1)",
            (warns[1] if len(warns) > 1 else r.stderr)[-200:])  # fmt: skip
        stf = e.state / "logs" / "mcp" / "status.json"
        st = json.loads(stf.read_text()) if stf.is_file() else {}
        states = {n: v.get("state") for n, v in st.get("servers", {}).items()}
        want_states = {n: "connected" for n in ("hostsrv", "ssesrv", "local", "time", "mem",
                                                *(["deepwiki"] if DEEPWIKI else []))}  # fmt: skip
        want_states["dead"] = want_states["evil"] = "failed"
        rec(states == want_states and not any(v in stf.read_text() for v in bearers.values()),
            "status.json: per-upstream state, no secrets", json.dumps(st)[:300])  # fmt: skip
        ids = container_ids()
        rec("mcp-gateway" in ids, "mcp-gateway container runs", ", ".join(sorted(ids)))
        # -- agent-controlled client configs: the CLI reads none of them; hostile
        # Pi home/project files do not reach Pi's adapter (exclusive managed config)
        codex_user = 'model = "o3"\n[mcp_servers.mine]\ncommand = "true"\n'
        deep = '{"mcpServers":{"deep":' + "[" * 100000 + "]" * 100000 + "}}"
        e.box(
            "mkdir -p ~/.codex ~/.pi/agent ~/.config/mcp ~/.agents .pi && "
            "printf 'x = [\\n' > ~/.codex/config.toml && "
            "mkfifo ~/.pi/agent/mcp.json && cat > ~/.config/mcp/mcp.json && "
            "ln -sf /dev/zero ~/.agents/mcp.json && ln -sf /dev/zero .pi/mcp.json && "
            """printf '{"mcpServers":{"proj":{"command":"sh"}}}' > .mcp.json""",
            input=deep,
        )  # fmt: skip
        t0 = time.time()
        r = e.ab("shell", NAME, "--", "true", timeout=120)
        dt = time.time() - t0
        rec(r.returncode == 0 and "Traceback" not in r.stderr and dt < 30,
            "hostile Pi files (200 KB deep nesting, FIFO, /dev/zero symlinks, project "
            "servers) + broken codex config.toml: session starts quickly",
            f"{dt:.1f}s " + " ".join(r.stderr.split())[-200:])  # fmt: skip
        t0 = time.time()
        pi_help = "timeout 60 pi --help >/dev/null 2>&1; echo rc=$?"
        r = e.ab("shell", NAME, "--", "sh", "-c", pi_help, timeout=120)
        dt = time.time() - t0
        rec("rc=0" in r.stdout and dt < 30, "pi (wrapper + adapter) starts with the hostile files",
            f"{dt:.1f}s {r.stdout.strip()}")  # fmt: skip
        r = e.ab("shell", NAME, "--", "env", "PI_MCP_CONFIG_MODE=exclusive", "node",
                 "--input-type=module", "-", input=PI_PROBE, timeout=300)  # fmt: skip
        rec("PI-SERVERS agentbox\n" in r.stdout and PI_WANT in r.stdout,
            "pi-mcp-adapter (managed config, exclusive) sees only agentbox and connects",
            " ".join((r.stdout + r.stderr).split())[-300:])  # fmt: skip
        e.box("rm -f ~/.pi/agent/mcp.json ~/.config/mcp/mcp.json ~/.agents/mcp.json "
              ".pi/mcp.json .mcp.json && "
              f"printf '%s' '{codex_user}' > ~/.codex/config.toml")  # fmt: skip
        r = e.ab("up", NAME)
        rec(r.returncode == 0, "re-up", " ".join(r.stderr.split())[-200:])
        cfg = e.box("cat ~/.codex/config.toml").stdout
        rec(cfg == codex_user.replace("\\n", "\n"),
            "codex config.toml untouched by agentbox", cfg.replace("\n", " | ")[:200])  # fmt: skip
        ov = " ".join(f"'{x}'" for x in CODEX_MCP_OVERRIDES)
        r = e.box(f"codex {ov} mcp list 2>/dev/null")
        rec("agentbox" in r.stdout and "http://mcp-gateway:8080/mcp" in r.stdout
            and "MCP_GATEWAY_TOKEN" in r.stdout and "mine" in r.stdout,
            "codex with the launch -c overrides lists agentbox (gateway URL, bearer env var)",
            " ".join(r.stdout.split())[:200])  # fmt: skip

        rec(None, "live Claude / Codex / Pi sessions call a gateway tool",
            "needs the user's Claude token and ChatGPT / Pi logins (P6 gate item 'works from "
            "Claude, Codex, Pi'); claude mcp list, codex mcp list, and the Pi adapter probe "
            "above cover config + connection")  # fmt: skip

        # -- from the agent: tools/list, allowed calls, rejected calls, auth
        out = e.client("list")
        listed = out.get("tools")
        if not rec(listed == WANT_TOOLS, "tools/list = allowlisted namespaced tools only",
                   json.dumps(out)[:400]):  # fmt: skip
            print(e.compose("logs", "--tail", "40", "mcp-gateway").stdout[-3000:])
        calls = {
            "hostsrv_allowed_a": ({"x": 41}, "A42"),
            "hostsrv_allowed_b": ({"text": argmark}, "B:" + argmark[::-1]),
            "ssesrv_allowed_a": ({"x": 1}, "A2"),
            "local_ping": ({}, "env-clean"),
            "time_get_current_time": ({"timezone": "UTC"}, "UTC"),
            "mem_read_graph": ({}, "entities"),
        }
        if DEEPWIKI:
            calls["deepwiki_read_wiki_structure"] = ({"repoName": "PrefectHQ/fastmcp"}, "")
        else:
            rec(None, "remote-style upstream (DeepWiki via CONNECT)",
                f"host cannot reach https://mcp.deepwiki.com/mcp: {DEEPWIKI_WHY}")  # fmt: skip
        for name, (args, want) in calls.items():
            t0 = time.time()
            res = e.client("call", name, json.dumps(args))
            ok = res.get("ok") and want in res.get("text", "")
            rec(bool(ok), f"allowed call {name}", f"{time.time() - t0:.1f}s "
                + json.dumps(res)[:200])  # fmt: skip
        out = e.client("probe", "{}", *DENY_CALLS)
        rej = {n: r for n, r in out.get("calls", {}).items()}
        rec(
            set(rej) == set(DENY_CALLS) and not any(r.get("ok") for r in rej.values()),
            "tools/call of non-allowlisted tools / unlisted servers rejected",
            "; ".join(f"{n}: {r.get('error')}"[:60] for n, r in rej.items())[:400],
        )
        stub_calls = e.stub_log.read_text().split("\n")
        rec(
            "http allowed_a" in stub_calls and "http allowed_b" in stub_calls
            and "sse allowed_a" in stub_calls
            and not any("forbidden" in x or x == "sse allowed_b" for x in stub_calls),
            "upstreams saw exactly the allowed calls, with their bearer (stub auth passed), "
            "and no agent header",
            " | ".join(x for x in stub_calls if x),
        )  # fmt: skip
        codes = {m: e.client("code", m).get("code") for m in ("none", "bad", "env")}
        rec(codes == {"none": 401, "bad": 401, "env": 200},
            "gateway auth: no token 401, wrong token 401, box token 200", str(codes))  # fmt: skip

        # -- gateway call log
        logf = e.state / "logs" / "mcp" / "calls.jsonl"
        lines = [json.loads(x) for x in logf.read_text().splitlines()] if logf.is_file() else []
        keys = {tuple(sorted(x)) for x in lines}
        text = logf.read_text() if logf.is_file() else ""
        ok_calls = {(x["server"], x["tool"]) for x in lines if x.get("status") == "ok"}
        denied = {x["tool"] for x in lines if x.get("status") == "denied"}
        rec(
            keys == {("args_sha256", "duration_ms", "server", "status", "time", "tool")}
            and ("hostsrv", "allowed_b") in ok_calls and ("ssesrv", "allowed_a") in ok_calls
            and {"forbidden", "forbidden_local"} <= denied
            and argmark not in text and argmark[::-1] not in text and "A42" not in text,
            f"gateway log: {len(lines)} JSON lines (time/server/tool/args_sha256/status/"
            "duration), no args, no results",
            f"keys {sorted(keys)[:2]} denied {sorted(denied)}",
        )  # fmt: skip

        # -- the agent cannot reach the upstreams itself
        r = e.box(
            "for p in " + f"{e.hport} {e.sport}" + "; do "
            "printf 'G%s %s\\n' $p $(curl -s -o /dev/null --noproxy '' -x http://egress:3128 "
            "-m 10 -w '%{http_code}' http://host.docker.internal:$p/mcp); "
            "printf 'D%s %s\\n' $p $(curl -s -o /dev/null --noproxy '*' -m 5 "
            "-w '%{http_code}' http://host.docker.internal:$p/mcp); done; "
            "printf 'C %s\\n' $(curl -s -o /dev/null --noproxy '' -x http://egress:3128 -m 10 "
            "-w '%{http_connect}' https://registry.npmjs.org/)"
        )
        got = dict(x.split() for x in r.stdout.splitlines() if len(x.split()) == 2)
        want = {f"G{e.hport}": "403", f"G{e.sport}": "403", f"D{e.hport}": "000",
                f"D{e.sport}": "000", "C": "403"}  # fmt: skip
        rec(got == want, "agent -> upstreams: via its proxy 403, direct no connection",
            str(got))  # fmt: skip

        # -- Claude: managed-mcp.json only, connected (no login needed for `mcp list`)
        r = e.box("claude mcp list 2>&1")
        lines_c = [x for x in r.stdout.splitlines() if ": " in x and not x.startswith("Checking")]
        rec(
            len(lines_c) == 1 and lines_c[0].startswith("agentbox: http://mcp-gateway:8080/mcp")
            and "✔ connected" in lines_c[0].lower() and "failed" not in lines_c[0].lower(),
            "claude mcp list: only agentbox, connected", " | ".join(lines_c)[:300],
        )  # fmt: skip
        proj_mcp = '{"mcpServers":{"x":{"type":"http","url":"http://example.com"}}}'
        r = e.box(
            f"cd /tmp && printf '%s' '{proj_mcp}' > .mcp.json && claude mcp list 2>&1; "
            "claude mcp add --transport http y http://example.com 2>&1; rm -f .mcp.json"
        )
        names = [x.split(":")[0] for x in r.stdout.splitlines() if ": http" in x]
        rec(names == ["agentbox"] and "Cannot add MCP server" in r.stdout,
            "claude ignores project .mcp.json / `mcp add` servers (managed-mcp.json)",
            " ".join(r.stdout.split())[:300])  # fmt: skip

        # -- doctor 13/14/20
        res = doctor(e)
        for c in ("13 (mcp-gateway)", "14 connectors-proxy", "14 claude-mcp", "14 codex-config",
                  "14 codex-mcp", "14 pi-mcp",
                  "20 auth", "20 policy", "20 upstream-direct", "20 gateway-fs"):  # fmt: skip
            st, d = res.get(c, ("-", "missing"))
            rec(st == "PASS", f"doctor {c}", d[:240])
        for c in ("14 codex-apps-live", "20 allowed-call", "13 (router)"):
            st, d = res.get(c, ("-", "missing"))
            rec(st == "SKIP", f"doctor {c} SKIP", d[:200])
        st, d = res.get("20 upstreams", ("-", "missing"))
        rec(st == "FAIL" and "dead (" in d and "evil (" in d and not any(
            f"{n} (" in d for n in ("hostsrv", "ssesrv", "local", "time", "mem", "deepwiki")),
            "doctor 20 upstreams FAILs naming only `dead`, `evil`", d[:240])  # fmt: skip
        raw = e.last_doctor
        rec(
            "PWNED" in raw and not any(c in raw for c in "\x1b\x07\x9b"),
            "doctor output: upstream error text escaped",
            "",
        )
        fails = {k: v for k, v in res.items() if v[0] == "FAIL" and k != "20 upstreams"}
        rec(not fails, "full doctor: no other FAIL", json.dumps(fails)[:500])

        # -- gateway container posture
        gid = container_ids().get("mcp-gateway", "")
        info = json.loads(sh(["docker", "inspect", gid]).stdout or "[{}]")[0]
        hc = info.get("HostConfig", {})
        nets = sorted(info.get("NetworkSettings", {}).get("Networks", {}))
        rec(
            hc.get("CapDrop") == ["ALL"]
            and "no-new-privileges:true" in (hc.get("SecurityOpt") or [])
            and hc.get("Memory") and hc.get("PidsLimit")
            and info["Config"]["User"] in ("mcpgw", "10002")
            and nets == [f"{PROJECT}_internal"],
            "gateway: cap_drop ALL, no-new-privileges, limits, non-root, "
            "internal network only",
            f"user {info['Config'].get('User')} nets {nets}",
        )  # fmt: skip
        r = e.compose("exec", "-T", "mcp-gateway", "sh", "-c",
                      "id -u; stat -c '%n %u %a' /run/secrets/*; "
                      "tr '\\0' '\\n' < /proc/1/environ | cut -d= -f1 | sort")  # fmt: skip
        rec(
            "10002" in r.stdout.split()[:1]
            and "/run/secrets/HOST_MCP_TOK 0 444" in r.stdout
            and "/run/secrets/MCP_GATEWAY_TOKEN 0 444" in r.stdout
            and "SSE_MCP_TOK" in r.stdout,
            "gateway /run/secrets: root 0444, readable by uid 10002",
            " | ".join(r.stdout.split("\n"))[:300],
        )  # fmt: skip

        # -- leak audit
        audit(e, bearers, "after calls + doctor")

        # -- egress log rotation at `up` (> 20 MB): squid reopens a fresh file,
        # `denied` reads the rotated one too
        elog = e.state / "logs" / "egress" / "egress.log"
        old_line = ("1790000000.000      0 10.0.0.1 TCP_DENIED/403 0 CONNECT "
                    "rotated-marker.example:443 - HIER_NONE/- text/html \"-\"\n")  # fmt: skip
        with elog.open("a") as f:
            f.write(old_line.replace("10.0.0.1", ips_agent(e)) * 2)
            f.write("#" * (21 * 1024 * 1024) + "\n")
        r = e.ab("up", NAME)
        e.box("curl -s -o /dev/null --noproxy '' -x http://egress:3128 -m 10 "
              "https://after-rotate.example.org/ || true")  # fmt: skip
        time.sleep(1)
        rot = elog.with_name("egress.log.1")
        new_ok = elog.is_file() and "after-rotate.example.org" in elog.read_text()
        dn = e.ab("denied", NAME, "--json")
        hosts = {d.get("host") for d in json.loads(dn.stdout or "[]")}
        rec(r.returncode == 0 and rot.is_file() and rot.stat().st_size > 20 * 1024 * 1024
            and elog.stat().st_size < 1024 * 1024 and new_ok
            and {"rotated-marker.example", "after-rotate.example.org"} <= hosts,
            "egress.log rotated at up; squid writes a fresh file; denied reads both",
            f"hosts {sorted(hosts)[:6]}")  # fmt: skip

        # -- zero servers: the gateway still runs with zero tools
        pf = e.roots / "config" / "profiles" / f"{NAME}.toml"
        pf.write_text(pf.read_text().split("[secrets]")[0])
        r = e.ab("up", NAME)
        out = e.client("list")
        rec(r.returncode == 0 and out.get("tools") == [],
            "profile without MCP servers: gateway runs, tools/list is empty",
            json.dumps(out)[:200])  # fmt: skip
        r = e.ab("down", NAME)
        rec(r.returncode == 0, "down")
        audit(e, bearers, "after down")
    except Exception as ex:  # noqa: BLE001
        rec(False, "smoke harness", repr(ex))
    finally:
        cleanup(e, before_vols)
    return finish()


def cleanup(e: Env, before_vols: set[str]) -> None:
    if getattr(e, "evil", None):
        e.evil.shutdown()
    for p in e.stubs:
        p.terminate()
        try:
            p.wait(timeout=10)
        except subprocess.TimeoutExpired:
            p.kill()
    f = e.state / "compose.json"
    if f.exists():
        sh(["docker", "compose", "-p", PROJECT, "-f", str(f), "down", "-v", "--remove-orphans",
            "--timeout", "2"])  # fmt: skip
    sh(["docker", "volume", "rm", "-f", f"{PROJECT}-home"])
    shutil.rmtree(e.work, ignore_errors=True)
    shutil.rmtree(e.roots, ignore_errors=True)
    shutil.rmtree(e.vault, ignore_errors=True)
    left = sh(["docker", "ps", "-a", "--format", "{{.Names}}"]).stdout.split()
    nets = sh(["docker", "network", "ls", "--format", "{{.Name}}"]).stdout.split()
    vols = sh(["docker", "volume", "ls", "--format", "{{.Name}}"]).stdout.split()
    ours = [x for x in left + nets + vols if NAME in x]
    new_vols = sorted(set(sh(["docker", "volume", "ls", "-q"]).stdout.split()) - before_vols)
    stubs_alive = [p.pid for p in e.stubs if p.poll() is None]
    rec(
        not ours and not new_vols and not stubs_alive
        and not any(p.exists() for p in (e.work, e.roots, e.vault)),
        "cleanup (containers, networks, volumes, dirs, stub processes)",
        f"leftovers {ours} {new_vols} {stubs_alive}",
    )  # fmt: skip


def finish() -> int:
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print(
        f"\nSUMMARY: {sum(r[0] == 'PASS' for r in RESULTS)} pass, {len(fails)} fail, "
        f"{sum(r[0] == 'SKIP' for r in RESULTS)} skip"
    )
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
