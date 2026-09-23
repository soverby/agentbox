"""MCP gateway wiring (PLAN §2.6, T5): gateway config, Compose service, egress
allowlist, and the agent-side wiring: Codex launch overrides; Claude and Pi use root-owned
files in the agent image (managed-mcp.json, /etc/agentbox/pi-mcp.json).

- Gateway config (`<state>/mcp-gateway/config.json`, bind-mounted ro): per
  server `url` or `command`, `bearer_env` (the secret NAME, never a value),
  `tools` (None = all tools of that server).
- Egress (gateway source): hostnames of remote `https://` server URLs;
  `http://host.docker.internal:<port>` URLs give the gateway-only
  non-CONNECT rule for those ports (§2.2); `uvx` stdio servers add PyPI.
- Stdio: the gateway image has Python + uv (`uvx`) and Node.js 24 (`npx`,
  `node`); other launchers (pnpm, yarn, bun, deno) are refused at render
  time. `uvx` adds PyPI, `npx`/`npm` add the npm registry to the gateway
  allowlist.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlsplit

from . import compose, network
from .profile import McpServer, Profile, hostname_problem, oauth_secret_name

SERVICE = "mcp-gateway"
PORT = 8080
URL = f"http://{SERVICE}:{PORT}/mcp"
TOKEN_ENV = "MCP_GATEWAY_TOKEN"
GW_UID = 10002
CONF_DIR = "/etc/mcp-gateway"
LOG_DIR = "/var/log/mcp"
LOG_NAME = "calls.jsonl"
STATUS_NAME = "status.json"
PROBE_ARGV = ["python3", "/opt/mcp-gateway/gateway.py", "probe"]
HOST_NAME = "host.docker.internal"
PYPI_DOMAINS = ["pypi.org", "files.pythonhosted.org"]
NPM_DOMAINS = ["registry.npmjs.org"]
UNSUPPORTED_LAUNCHERS = ("pnpm", "pnpx", "yarn", "bunx", "bun", "deno")
LIMITS = {"mem_limit": "512m", "pids_limit": 256}
GW_NO_PROXY = "localhost,127.0.0.1"
CONFIG_LABEL = "agentbox.mcp-config"
# OAuth upstreams (P6b): rotated token sets live in a gateway-only named volume.
OAUTH_DIR = "/var/lib/mcp-oauth"
OAUTH_HOSTS_FILE = "mcp-oauth-hosts.json"  # state: token/revocation endpoint hosts (no tokens)
OAUTH_ARGV = ["python3", "/opt/mcp-gateway/gateway.py"]


def oauth_volume(profile: str) -> str:
    return f"agentbox-{profile}-mcp-oauth"


def has_oauth(profile: Profile) -> bool:
    return any(s.auth == "oauth" for s in profile.mcp_servers.values())


class McpError(ValueError):
    pass


def namespace_problem(names: list[str]) -> str | None:
    """Same rule as the gateway: `<server>_<tool>` must map to one server."""
    for a in names:
        for b in names:
            if a != b and b.startswith(a + "_"):
                return f"MCP server names {a!r} and {b!r} clash in '<server>_<tool>' tool names"
    return None


def _split_url(s: McpServer) -> tuple[str, str, int]:
    u = urlsplit(s.url or "")
    host = (u.hostname or "").lower()
    try:
        port = u.port
    except ValueError:
        raise McpError(f"mcp.servers.{s.name}: invalid port in {s.url!r}") from None
    if port is None:
        port = 443 if u.scheme == "https" else 80
    return u.scheme, host, port


def host_server(s: McpServer) -> bool:
    return s.url is not None and _split_url(s)[1] == HOST_NAME


def check(profile: Profile) -> None:
    """Hard errors for servers the gateway cannot reach through squid."""
    names = list(profile.mcp_servers)
    if msg := namespace_problem(names):
        raise McpError(msg)
    for s in profile.mcp_servers.values():
        where = f"mcp.servers.{s.name}"
        if s.command is not None:
            exe = s.command[0].rsplit("/", 1)[-1]
            if exe in UNSUPPORTED_LAUNCHERS:
                raise McpError(
                    f"{where}: {exe!r} is not in the mcp-gateway image; stdio servers run "
                    "with uvx, python3, npx, or node (or use a url server)"
                )
            continue
        scheme, host, port = _split_url(s)
        if host == HOST_NAME:
            if s.auth == "oauth":
                raise McpError(f'{where}: auth = "oauth" needs a remote https:// server')
            if scheme != "http":
                raise McpError(f"{where}: host MCP servers must use http://{HOST_NAME}:<port>/")
            continue
        if host in ("localhost", "127.0.0.1", "::1", "gateway.docker.internal"):
            raise McpError(f"{where}: {host} is not reachable; use http://{HOST_NAME}:<port>/")
        if scheme != "https":
            raise McpError(f"{where}: remote MCP servers must use https:// (squid allows only "
                           "CONNECT to port 443)")  # fmt: skip
        if port != 443:
            raise McpError(f"{where}: remote MCP servers must use port 443")
        if msg := hostname_problem(host):
            raise McpError(f"{where}: {host!r}: {msg}")


def gateway_config(profile: Profile) -> dict:
    check(profile)
    servers = {}
    for s in profile.mcp_servers.values():
        servers[s.name] = {
            "url": s.url,
            "command": list(s.command) if s.command else None,
            "bearer_env": s.bearer,
            "tools": list(s.tools) if s.tools else None,
        }
        if s.auth == "oauth":
            servers[s.name]["oauth_env"] = oauth_secret_name(s.name)
    if has_oauth(profile):  # the gateway names `agentbox mcp login <profile> <server>`
        return {"profile": profile.name, "servers": servers}
    return {"servers": servers}


def config_text(profile: Profile) -> str:
    return json.dumps(gateway_config(profile), indent=1, sort_keys=True) + "\n"


def oauth_hosts(state: Path | None, profile: Profile) -> list[str]:
    """Token / revocation endpoint hosts recorded by `agentbox mcp login`
    (state file, names only) for the profile's OAuth servers."""
    if state is None:
        return []
    f = state / OAUTH_HOSTS_FILE
    try:
        data = json.loads(f.read_text()) if f.is_file() else {}
    except ValueError:
        return []
    out = []
    for name, s in profile.mcp_servers.items():
        rec = data.get(name) if isinstance(data, dict) else None
        if s.auth != "oauth" or not isinstance(rec, dict):
            continue
        for h in rec.get("hosts", []):
            if isinstance(h, str) and not hostname_problem(h):
                out.append(h.lower())
    return out


def egress_domains(profile: Profile, state: Path | None = None) -> list[str]:
    out: list[str] = list(oauth_hosts(state, profile))
    for s in profile.mcp_servers.values():
        if s.url is not None and not host_server(s):
            out.append(_split_url(s)[1])
        elif s.command and s.command[0].rsplit("/", 1)[-1] in ("uvx", "uv"):
            out += PYPI_DOMAINS
        elif s.command and s.command[0].rsplit("/", 1)[-1] in ("npx", "npm"):
            out += NPM_DOMAINS
    return sorted(set(out))


def host_ports(profile: Profile) -> list[int]:
    return sorted({_split_url(s)[2] for s in profile.mcp_servers.values() if host_server(s)})


def conf_dir(ctx: compose.Ctx):
    return ctx.state / "mcp-gateway"


def log_dir(ctx: compose.Ctx):
    return ctx.state / "logs" / "mcp"


def service(ctx: compose.Ctx) -> dict:
    ips = network.fixed_ips(ctx.n, ctx.base)
    env = {
        "HTTPS_PROXY": compose.PROXY,
        "HTTP_PROXY": compose.PROXY,
        "https_proxy": compose.PROXY,
        "http_proxy": compose.PROXY,
        "NO_PROXY": GW_NO_PROXY,
        "no_proxy": GW_NO_PROXY,
    }
    return {
        "image": ctx.gateway_image,
        "init": True,
        "networks": {"internal": {"ipv4_address": ips[SERVICE]}},
        "environment": env,
        "volumes": [
            f"{conf_dir(ctx)}:{CONF_DIR}:ro",
            f"{log_dir(ctx)}:{LOG_DIR}",
        ],
        # exec: `uvx` runs the entry points it installs under /tmp (Docker's
        # tmpfs default is noexec: "Failed to spawn … Permission denied").
        "tmpfs": [f"/tmp:uid={GW_UID},gid={GW_UID},mode=0700,exec"],
        **compose.HARDEN,
        # No `read_only`: Compose refuses `secrets:` with an `environment:`
        # source on a read-only service (PLAN §2.1, R1-01; confirmed again in
        # P6). The image leaves no system path writable by uid 10002; doctor
        # "20 gateway-fs" checks it.
        **LIMITS,
        **(
            {
                "volumes": [
                    f"{conf_dir(ctx)}:{CONF_DIR}:ro",
                    f"{log_dir(ctx)}:{LOG_DIR}",
                    f"mcpoauth:{OAUTH_DIR}",
                ]
            }
            if has_oauth(ctx.profile)
            else {}
        ),  # fmt: skip
        "labels": {CONFIG_LABEL: compose.config_hash({"config.json": config_text(ctx.profile)})},
    }


# --- agent-side client configs ---

# Codex: `-c` launch overrides (launch.CODEX_MCP_OVERRIDES), never its file.
CODEX_MCP = {"url": URL, "bearer_token_env_var": TOKEN_ENV, "enabled": True}

# Pi: the agent image's root-owned /etc/agentbox/pi-mcp.json (pi-wrapper passes
# it with --mcp-config in exclusive mode). The CLI never touches Pi's home files.
PI_MCP_FILE = "/etc/agentbox/pi-mcp.json"
PI_ENTRY = {"url": URL, "auth": "bearer", "bearerTokenEnv": TOKEN_ENV}
