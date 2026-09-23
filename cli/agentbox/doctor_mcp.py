"""Doctor checks for the MCP path (PLAN §4 checks 13, 14; new check 20).

- 13 (mcp-gateway): run inside the real gateway container (Python, no curl
  there): no external DNS, no direct TCP, via the proxy only the gateway
  allowlist, host MCP ports only as plain forward requests.
- 14: `mcp-proxy.anthropic.com` → 403 from the agent; `claude mcp list` shows
  only `agentbox`, connected; Codex effective config with the launch `-c`
  overrides against a config that turns apps / remote plugins on; the live
  "no apps" part needs a ChatGPT login.
- 20 (gateway policy, new): no / wrong token → 401; `tools/list` holds only
  allowlisted `<server>_<tool>` names; a non-allowlisted name and an unlisted
  server are rejected by `tools/call`; the agent cannot reach any upstream
  directly through its own proxy ACL. Doctor never calls a user tool (tools
  can have side effects); the P6 smoke covers a real allowed call.
"""

from __future__ import annotations

import json
import re
import shlex

from . import box as boxmod
from . import compose, docker, launch, mcpgw, paths
from .denied import allow_matches

GW_PROBE = r"""
import http.client, socket, sys
ua, allowed, denied, ports, deny_ports = sys.argv[1:6]
ports = [int(p) for p in ports.split()]
deny_ports = [int(p) for p in deny_ports.split()]
bad = []
notes = []
def px():
    return http.client.HTTPConnection("egress", 3128, timeout=15)
def connect(hp):
    c = px()
    try:
        c.request("CONNECT", hp, headers={"Host": hp, "User-Agent": ua})
        r = c.getresponse()
        return r.status, r.getheader("X-Squid-Error") or ""
    except OSError as e:
        return f"error {e}", ""
    finally:
        c.close()
def plain(url):
    c = px()
    try:
        c.request("GET", url, headers={"User-Agent": ua})
        r = c.getresponse()
        return r.status, r.getheader("X-Squid-Error")
    except OSError as e:
        return f"error {e}", None
    finally:
        c.close()
try:
    socket.getaddrinfo("example.com", 443)
    bad.append("external name resolves in the gateway")
except OSError:
    pass
for hp in (("1.1.1.1", 443), ("host.docker.internal", 80)):
    try:
        socket.create_connection(hp, timeout=4).close()
        bad.append(f"direct TCP {hp[0]}:{hp[1]} connected")
    except OSError:
        pass
if allowed:
    s, err = connect(f"{allowed}:443")
    if s in (502, 503, 504) and err and not err.startswith("ERR_ACCESS_DENIED"):
        notes.append(f"{allowed} allowed by the ACL, upstream unreachable ({s} {err.split()[0]})")
    elif s != 200:
        bad.append(f"CONNECT {allowed}:443 -> {s} {err} (want 200)")
for hp in (f"{denied}:443", "1.1.1.1:443", "mcp-proxy.anthropic.com:443"):
    s, _ = connect(hp)
    if s != 403:
        bad.append(f"CONNECT {hp} -> {s} (want 403)")
for p in ports:
    s, err = plain(f"http://host.docker.internal:{p}/")
    if s == 403 or (err or "").startswith("ERR_ACCESS_DENIED") or not isinstance(s, int):
        bad.append(f"GET host MCP :{p} -> {s} {err or ''} (want: not denied by squid)")
    elif err:
        notes.append(f"host MCP :{p} allowed by the ACL, not answering ({err.split()[0]})")
    s, _ = connect(f"host.docker.internal:{p}")
    if s != 403:
        bad.append(f"CONNECT host.docker.internal:{p} -> {s} (want 403)")
for p in deny_ports:
    s, err = plain(f"http://host.docker.internal:{p}/")
    if s != 403:
        bad.append(f"GET host :{p} (not an MCP port) -> {s} (want 403)")
if bad:
    print("FAIL 13 (mcp-gateway): " + "; ".join(bad + notes))
else:
    notes = notes or ["direct egress fails; proxy: own allowlist only"]
    print("PASS 13 (mcp-gateway): " + "; ".join(notes))
"""

# The gateway service is not read_only (Compose env-source secrets): prove that
# its user can write only /tmp (tmpfs) and the log dir, and runs as non-root.
GW_FS = r"""
import os, stat
allowed = ("/tmp", "/var/log/mcp", "/var/lib/mcp-oauth")
skip = ("/proc", "/sys", "/dev")
bad = []
if os.getuid() == 0:
    bad.append("gateway runs as root")
for top, dirs, files in os.walk("/"):
    if top.startswith(skip) or top.startswith(allowed):
        dirs[:] = []
        continue
    for n in dirs + files:
        p = os.path.join(top, n)
        if p.startswith(skip + allowed) or os.path.islink(p):
            continue
        try:
            st = os.lstat(p)
        except OSError:
            continue
        if os.access(p, os.W_OK):
            bad.append(f"writable {p}")
        if stat.S_ISREG(st.st_mode) and st.st_mode & (stat.S_ISUID | stat.S_ISGID):
            bad.append(f"setuid/setgid {p}")
    if len(bad) > 20:
        break
if bad:
    print("FAIL 20 gateway-fs: " + "; ".join(bad[:20]))
else:
    print(f"PASS 20 gateway-fs: uid {os.getuid()}; writable only {', '.join(allowed)}")
"""

PROXY_NAME = "mcp-proxy.anthropic.com"
CLAUDE_LINE = re.compile(r"^([A-Za-z0-9_.:-]+): (\S+)(.*)$")


def _result(status, check, detail=""):
    from .doctor import Result

    return Result(status, check, detail)


def pick_gateway_allowed(domains: list[str]) -> str:
    return next((d for d in domains if not d.startswith(".")), "")


def check_13(b: boxmod.Box, ua: str) -> list:
    from .doctor import parse_lines, pick_denied

    p = b.profile
    doms = mcpgw.egress_domains(p, b.state)
    ports = mcpgw.host_ports(p)
    deny_ports = [x for x in (11434, 3128, 22) if x not in ports]
    args = [ua, pick_gateway_allowed(doms), pick_denied(doms), " ".join(map(str, ports)),
            " ".join(map(str, deny_ports))]  # fmt: skip
    r = boxmod.dc(
        b, "exec", "-T", mcpgw.SERVICE, "python3", "-", *args,
        input=GW_PROBE, check=False, timeout=120,
    )  # fmt: skip
    res = parse_lines(r.stdout)
    if not res:
        res = [_result("FAIL", "13 (mcp-gateway)", f"no result: {r.stderr.strip()[-300:]}")]
    if not doms:
        res[0].detail = "; ".join(
            x for x in (res[0].detail, "gateway allowlist is empty: allowed case not tested") if x
        )
    if compose.has_router(p):
        from . import doctor_router

        res += doctor_router.check_13(b, ua)
    else:
        res.append(_result("SKIP", "13 (router)", "no [models.remote.*] in this profile"))
    return res


def client_text() -> str:
    return (paths.repo_root() / "tests" / "isolation" / "mcp_client.py").read_text()


def mcp_client(b: boxmod.Box, *args: str) -> dict:
    r = boxmod.exec_in(b, ["python3", "-", *args], input=client_text(), timeout=180)
    try:
        return json.loads(r.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return {"error": f"exit {r.returncode}: {r.stderr.strip()[-300:]}"}


def parse_claude_mcp_list(out: str) -> dict[str, str]:
    """{name: rest of line} from `claude mcp list`."""
    servers = {}
    for line in out.splitlines():
        m = CLAUDE_LINE.match(line.strip())
        if m and m.group(1) not in ("Checking", "Warning", "Error", "Note"):
            servers[m.group(1)] = (m.group(2) + m.group(3)).strip()
    return servers


# The file a user could write: apps and remote plugins on. The check reads the
# effective values with the launch overrides (the same tuple agent_argv uses).
CODEX_HOSTILE = "[features]\napps = true\nremote_plugin = true\n\n[apps._default]\nenabled = true\n"
CODEX_FEATURES = r"""
set -eu
d=$(mktemp -d "$HOME/.agentbox-doctor-codex.XXXXXX")
trap 'rm -rf "$d"' EXIT
cat > "$d/config.toml"
echo '== plain'
CODEX_HOME=$d codex features list 2>/dev/null
echo '== launch'
CODEX_HOME=$d codex "$@" features list 2>/dev/null
"""


def features(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[-1] in ("true", "false"):
            out[parts[0]] = parts[-1]
    return out


def check_codex_effective(b: boxmod.Box) -> list:
    r = boxmod.exec_in(
        b, ["sh", "-c", CODEX_FEATURES, "sh", *launch.CODEX_OVERRIDES],
        input=CODEX_HOSTILE, timeout=120,
    )  # fmt: skip
    plain, _, launched = r.stdout.partition("== launch")
    f0, f1 = features(plain), features(launched)
    reasons = []
    for k in ("apps", "remote_plugin"):
        if f0.get(k) != "true":
            reasons.append(f"control: config apps=true not effective ({k}={f0.get(k)})")
        if f1.get(k) != "false":
            reasons.append(f"with launch overrides {k}={f1.get(k)} (want false)")
    res = [_result("FAIL" if reasons else "PASS", "14 codex-config",
                   "; ".join(reasons) or "config sets apps/remote_plugin=true; effective with "
                   "the launch -c overrides: apps=false remote_plugin=false "
                   f"(plugins={f1.get('plugins')})")]  # fmt: skip
    # The box's real config + the launch overrides: the gateway entry Codex uses.
    r = boxmod.exec_in(
        b, ["codex", *launch.CODEX_MCP_OVERRIDES, "mcp", "get", "agentbox", "--json"], timeout=60
    )
    try:
        t = json.loads(r.stdout[r.stdout.index("{") :]).get("transport", {})
    except ValueError:
        t = {}
    ok = t.get("url") == mcpgw.URL and t.get("bearer_token_env_var") == mcpgw.TOKEN_ENV
    res.append(_result("PASS" if ok else "FAIL", "14 codex-mcp",
                       f"launch overrides -> agentbox {mcpgw.URL} (bearer env {mcpgw.TOKEN_ENV})"
                       if ok else "Codex does not load the gateway entry with the launch "
                       f"overrides (box ~/.codex/config.toml conflicts?): "
                       f"{' '.join((r.stdout + r.stderr).split())[-200:]}"))  # fmt: skip
    r = boxmod.exec_in(b, ["codex", "login", "status"], timeout=60)
    low = (r.stdout + r.stderr).lower()
    if r.returncode != 0 or "not logged in" in low or "logged in" not in low:
        res.append(_result("SKIP", "14 codex-apps-live",
                           "no ChatGPT login in this box: the live 'lists no apps / no remote "
                           "plugins' part needs `agentbox login <profile> codex`"))  # fmt: skip
    else:
        res.append(_result("SKIP", "14 codex-apps-live",
                           "logged in, but an automated live apps listing is not implemented: "
                           "check `/apps` in a CLI-launched Codex session by hand"))  # fmt: skip
    return res


PI_ADAPTER = "/usr/local/lib/agentbox/pi-mcp-adapter/node_modules/pi-mcp-adapter/dist"
PI_CHECK = r"""
set -u
stat -c 'STAT %U:%G %a %n' /etc/agentbox/pi-mcp.json /etc/agentbox
{ test -w /etc/agentbox/pi-mcp.json || test -w /etc/agentbox; } && echo WRITABLE
grep -qx 'MCP_CONFIG=/etc/agentbox/pi-mcp.json' /usr/local/bin/pi &&
  grep -q -- '--extension "$ADAPTER" --mcp-config "$MCP_CONFIG"' /usr/local/bin/pi &&
  grep -qx 'PI_MCP_CONFIG_MODE=exclusive' /usr/local/bin/pi && echo WRAPPER_OK
cd "$1" && printf '%s' "$2" |
  PI_MCP_CONFIG_MODE=exclusive timeout 30 node --input-type=module - 2>&1 | tail -1
"""
PI_LOAD = f"""
import {{ loadMcpConfig }} from "{PI_ADAPTER}/config.js";
const c = loadMcpConfig("/etc/agentbox/pi-mcp.json", process.cwd());
console.log("PI_SERVERS " + JSON.stringify(c.mcpServers));
"""


def check_pi(b: boxmod.Box):
    """Pi reads only the root-owned managed config (pi-wrapper: --mcp-config +
    exclusive mode), whatever the agent puts in its home or project files.
    Runs the installed adapter's own loader in the first mount (project files)."""
    r = boxmod.exec_in(
        b, ["sh", "-c", PI_CHECK, "sh", b.profile.mounts[0].path, PI_LOAD], timeout=90
    )
    out = r.stdout
    reasons = []
    stats = [x.split()[1:3] for x in out.splitlines() if x.startswith("STAT ")]
    if stats != [["root:root", "644"], ["root:root", "755"]]:
        reasons.append(f"/etc/agentbox/pi-mcp.json owner/mode {stats}")
    if "WRITABLE" in out:
        reasons.append("pi-mcp.json or /etc/agentbox writable by the agent")
    if "WRAPPER_OK" not in out:
        reasons.append("/usr/local/bin/pi does not pass --mcp-config with exclusive mode")
    line = next((x for x in out.splitlines() if x.startswith("PI_SERVERS ")), "")
    try:
        servers = json.loads(line[len("PI_SERVERS ") :]) if line else None
    except ValueError:
        servers = None
    if servers != {"agentbox": mcpgw.PI_ENTRY}:
        reasons.append(f"adapter loads {line[:200] or out.strip()[-200:]!r}")
    return _result("FAIL" if reasons else "PASS", "14 pi-mcp", "; ".join(reasons) or
                   "root-owned /etc/agentbox/pi-mcp.json via --mcp-config (exclusive); "
                   "the adapter loads only agentbox")  # fmt: skip


def check_14(b: boxmod.Box, ua: str) -> list:
    p = b.profile
    res = []
    r = boxmod.exec_in(
        b, ["curl", "-A", ua, "-s", "-o", "/dev/null", "--noproxy", "", "-x",
            "http://egress:3128", "-m", "15", "-w", "%{http_connect}",
            f"https://{PROXY_NAME}/"], timeout=60,
    )  # fmt: skip
    code = r.stdout.strip()
    if code == "403":
        res.append(_result("PASS", "14 connectors-proxy",
                           f"{PROXY_NAME} -> 403 ({p.network.mode} mode)"))  # fmt: skip
    else:
        res.append(_result("FAIL", "14 connectors-proxy", f"{PROXY_NAME} -> {code} (want 403)"))
    if "claude" in p.box.agents:
        r = boxmod.exec_in(b, ["claude", "mcp", "list"], timeout=120)
        servers = parse_claude_mcp_list(r.stdout)
        ok = list(servers) == ["agentbox"] and "connected" in servers["agentbox"].lower()
        ok = ok and mcpgw.URL in servers["agentbox"] and "failed" not in servers["agentbox"]
        detail = "; ".join(f"{k}: {v}" for k, v in servers.items()) or (
            f"no servers listed (exit {r.returncode}): {(r.stdout + r.stderr).strip()[-200:]}"
        )
        res.append(_result("PASS" if ok else "FAIL", "14 claude-mcp", detail))
    else:
        res.append(_result("SKIP", "14 claude-mcp", "claude is not in [box] agents"))
    if "pi" in p.box.agents:
        res.append(check_pi(b))
    else:
        res.append(_result("SKIP", "14 pi-mcp", "pi is not in [box] agents"))
    if "codex" in p.box.agents:
        res += check_codex_effective(b)
    else:
        res.append(_result("SKIP", "14 codex-config", "codex is not in [box] agents"))
    return res


NOT_ALLOWED_TOOL = "agentbox-doctor-not-allowed"
NO_SERVER = "agentbox-doctor-no-server"


def check_gateway_fs(b: boxmod.Box):
    from .doctor import parse_lines

    r = boxmod.dc(b, "exec", "-T", mcpgw.SERVICE, "python3", "-", input=GW_FS, check=False,
                  timeout=300)  # fmt: skip
    res = parse_lines(r.stdout)
    return res[0] if res else _result("FAIL", "20 gateway-fs", r.stderr.strip()[-300:])


def failed_upstreams(status: dict) -> list[str]:
    """'name (reason)' for each upstream that did not connect."""
    return [f"{n} ({s.get('reason', '?')})" for n, s in sorted(status.get("servers", {}).items())
            if s.get("state") != "connected"]  # fmt: skip


def check_upstreams(b: boxmod.Box):
    if not b.profile.mcp_servers:
        return _result("PASS", "20 upstreams", "no MCP servers declared")
    try:
        st = boxmod.gateway_status(b)
    except boxmod.BoxError as e:
        return _result("FAIL", "20 upstreams", str(e))
    bad = failed_upstreams(st)
    if bad:
        return _result("FAIL", "20 upstreams", "not connected: " + "; ".join(bad))
    notes = []
    for n, s in sorted(st["servers"].items()):
        if s.get("missing_allowed"):
            notes.append(f"{n}: allowlisted but not offered: {', '.join(s['missing_allowed'])}")
    detail = f"{len(st['servers'])} upstream(s) connected" + "".join("; " + x for x in notes)
    return _result("PASS", "20 upstreams", detail)


OAUTH_FS = r"""
import os, stat, sys
d = sys.argv[1]
bad = []
st = os.stat(d)
if st.st_uid != os.getuid() or stat.S_IMODE(st.st_mode) != 0o700:
    bad.append(f"{d} uid {st.st_uid} mode {stat.S_IMODE(st.st_mode):o} (want {os.getuid()} 700)")
for n in os.listdir(d):
    m = stat.S_IMODE(os.lstat(os.path.join(d, n)).st_mode)
    if m & 0o077:
        bad.append(f"{n} mode {m:o}")
print("BAD " + "; ".join(bad) if bad else f"OK {len(os.listdir(d))} file(s)")
"""


def check_oauth_store(b: boxmod.Box):
    """P6b: the OAuth token volume is on the gateway only (0700, gateway uid)."""
    if not mcpgw.has_oauth(b.profile):
        return _result("SKIP", "20 oauth-store", 'no auth = "oauth" MCP servers')
    reasons = []
    vol = mcpgw.oauth_volume(b.profile.name)
    # Live mounts of every container that uses the volume (any project).
    r = docker.run(["docker", "ps", "-a", "-q", "--filter", f"volume={vol}"], check=False)
    ids = r.stdout.split()
    users = []
    if ids:
        r = docker.run(["docker", "inspect", *ids], check=False)
        try:
            info = json.loads(r.stdout or "[]")
        except ValueError:
            info = []
        for c in info:
            mounts = [m for m in c.get("Mounts", []) if m.get("Name") == vol]
            if not mounts:
                continue
            labels = c.get("Config", {}).get("Labels") or {}
            svc = labels.get("com.docker.compose.service", "?")
            proj = labels.get("com.docker.compose.project", "?")
            users.append(f"{proj}/{svc}")
            if svc != mcpgw.SERVICE or proj != b.project:
                reasons.append(f"{proj}/{svc} ({c.get('Name', '?').lstrip('/')}) mounts {vol}")
            elif any(m.get("Destination") != mcpgw.OAUTH_DIR for m in mounts):
                reasons.append(f"gateway mounts {vol} outside {mcpgw.OAUTH_DIR}")
    if f"{b.project}/{mcpgw.SERVICE}" not in users:
        reasons.append(f"mcp-gateway does not mount {vol}")
    r = boxmod.dc(b, "exec", "-T", mcpgw.SERVICE, "python3", "-", mcpgw.OAUTH_DIR,
                  input=OAUTH_FS, check=False, timeout=60)  # fmt: skip
    out = r.stdout.strip()
    if not out.startswith("OK"):
        reasons.append(f"gateway: {out or r.stderr.strip()[-200:]}")
    r = boxmod.exec_in(b, ["sh", "-c", f"test -e {mcpgw.OAUTH_DIR} && echo SEEN || echo NONE"],
                       timeout=60)  # fmt: skip
    if "NONE" not in r.stdout:
        reasons.append(f"agent sees {mcpgw.OAUTH_DIR}")
    return _result("FAIL" if reasons else "PASS", "20 oauth-store",
                   "; ".join(reasons) or f"gateway-only volume, 0700 uid {mcpgw.GW_UID}; "
                   f"{out[3:]}; agent has no path to it")  # fmt: skip


def check_20(b: boxmod.Box, ua: str, agent_allowlist: list[str]) -> list:
    p = b.profile
    res = [check_gateway_fs(b), check_upstreams(b)]
    if mcpgw.has_oauth(p):  # P6b; no line for profiles without OAuth servers
        res.append(check_oauth_store(b))
    codes = {m: mcp_client(b, "code", m).get("code") for m in ("none", "bad", "env")}
    ok = codes["none"] == 401 and codes["bad"] == 401 and codes["env"] == 200
    res.append(_result("PASS" if ok else "FAIL", "20 auth",
                       f"no token -> {codes['none']}, wrong token -> {codes['bad']}, "
                       f"box token -> {codes['env']} (want 401, 401, 200)"))  # fmt: skip
    servers = list(p.mcp_servers)
    probes = [f"{s}_{NOT_ALLOWED_TOOL}" for s in servers if p.mcp_servers[s].tools] + [
        f"{NO_SERVER}_tool"
    ]
    out = mcp_client(b, "probe", "{}", *probes)
    reasons = []
    if "error" in out:
        reasons.append(str(out["error"]))
    listed = out.get("list", [])
    for name in listed:
        srv = next((s for s in servers if name.startswith(s + "_")), None)
        tools = p.mcp_servers[srv].tools if srv else None
        if srv is None or (tools is not None and name[len(srv) + 1 :] not in tools):
            reasons.append(f"tools/list has non-allowlisted {name}")
    for name, r in out.get("calls", {}).items():
        if r.get("ok"):
            reasons.append(f"tools/call {name} was not rejected")
    res.append(_result("FAIL" if reasons else "PASS", "20 policy",
                       "; ".join(reasons) or f"{len(listed)} allowlisted tool(s) listed; "
                       f"rejected: {', '.join(out.get('calls', {}))}"))  # fmt: skip
    # The agent reaches no upstream except through the gateway.
    reasons = []
    targets = [f"{d}:443" for d in mcpgw.egress_domains(p, b.state)
               if p.network.mode == "strict" and not allow_matches(d, agent_allowlist)]  # fmt: skip
    ports = mcpgw.host_ports(p)
    curl = f"curl -A {shlex.quote(ua)} -s -o /dev/null --noproxy '' -x http://egress:3128 -m 15"
    script = ["set -u"]
    for t in targets:
        script.append(f"echo C {t} $({curl} -w '%{{http_connect}}' https://{t}/)")
    for port in ports:
        u = f"http://host.docker.internal:{port}/"
        script.append(f"echo G {port} $({curl} -w '%{{http_code}}' {u})")
    if len(script) > 1:
        r = boxmod.exec_in(b, ["bash", "-c", "\n".join(script)], timeout=120)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) == 3 and parts[2] != "403":
                reasons.append(f"agent {parts[0]} {parts[1]} -> {parts[2]} (want 403)")
    shared = [d for d in mcpgw.egress_domains(p, b.state) if allow_matches(d, agent_allowlist)]
    note = f"; also on the agent allowlist (reachable by design): {', '.join(shared)}" if (
        shared and p.network.mode == "strict") else ""  # fmt: skip
    res.append(_result("FAIL" if reasons else "PASS", "20 upstream-direct",
                       "; ".join(reasons) or f"agent -> {len(targets)} upstream host(s), "
                       f"{len(ports)} host port(s): 403{note}"))  # fmt: skip
    why = "doctor never calls user MCP tools (side effects); p6_smoke covers it"
    res.append(_result("SKIP", "20 allowed-call", why))
    return res
