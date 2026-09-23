"""agentbox MCP gateway (PLAN §2.6, T5).

One streamable-HTTP endpoint (`:8080/mcp`) in front of the profile's MCP
servers. FastMCP 4.0.x APIs used (checked against the 4.0.5 source):

- `fastmcp.server.create_proxy(Client(transport))` per upstream
  (`server/server.py`), mounted with `FastMCP.mount(proxy, namespace=name)`:
  tools appear as `<server>_<tool>` (FastMCP's namespace convention).
- `Provider.enable(names=…, components={"tool"}, only=True)`
  (`server/providers/base.py`): allowlist mode on each proxy, so resources,
  templates, prompts, and unlisted tools are disabled (not listed, not
  callable) at the upstream provider.
- `StaticTokenVerifier` (`server/auth/providers/jwt.py`) as `auth=`: every
  HTTP request needs `Authorization: Bearer <MCP_GATEWAY_TOKEN>`, else 401.
- A `Middleware` (`server/middleware/middleware.py`) is the second policy
  layer: `tools/list` is filtered again, `tools/call` of a name outside the
  allowlist is rejected, resources and prompts are empty / rejected, and
  every call is logged as one JSON line (never arguments or results).

Upstream transports: `url` whose path ends in `/sse` → SSE, else streamable
HTTP. HTTP clients honour HTTPS_PROXY/HTTP_PROXY (squid). stdio servers run
inside this container with a minimal env (no secrets).
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

PORT = 8080
PATH = "/mcp"
TOKEN_ENV = "MCP_GATEWAY_TOKEN"
CONFIG = "/etc/mcp-gateway/config.json"
LOG_DIR = "/var/log/mcp"
LOG_FILE = f"{LOG_DIR}/calls.jsonl"
NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
TOOL_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
ENV_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
# Env for stdio servers: nothing from the gateway env except these names.
STDIO_ENV = ("PATH", "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy",
             "NO_PROXY", "no_proxy", "LANG", "UV_CACHE_DIR", "UV_PYTHON_PREFERENCE",
             "NPM_CONFIG_CACHE", "NPM_CONFIG_UPDATE_NOTIFIER")  # fmt: skip
STATUS_FILE = f"{LOG_DIR}/status.json"
SECRETS_DIR = "/run/secrets"
PROBE_TIMEOUT = 120.0  # first `npx` / `uvx` start installs packages
STDIO_HOME = "/tmp/stdio-home"


class ConfigError(Exception):
    pass


def load_config(data: Any) -> dict[str, dict]:
    """Validate the rendered config. Any unknown key or bad value is an error."""
    if not isinstance(data, dict) or set(data) - {"servers", "profile"}:
        raise ConfigError("config must be an object with only 'servers' and 'profile'")
    if "profile" in data and (
        not isinstance(data["profile"], str) or not NAME_RE.fullmatch(data["profile"])
    ):
        raise ConfigError("invalid profile name")
    servers = data.get("servers", {})
    if not isinstance(servers, dict):
        raise ConfigError("servers must be an object")
    out: dict[str, dict] = {}
    for name, s in servers.items():
        if not isinstance(name, str) or not NAME_RE.fullmatch(name):
            raise ConfigError(f"invalid server name {name!r}")
        if not isinstance(s, dict) or set(s) - {"url", "command", "bearer_env", "tools",
                                                  "oauth_env"}:  # fmt: skip
            raise ConfigError(f"{name}: unknown keys")
        url, cmd = s.get("url"), s.get("command")
        if (url is None) == (cmd is None):
            raise ConfigError(f"{name}: needs exactly one of url or command")
        if url is not None and (
            not isinstance(url, str) or not url.startswith(("http://", "https://"))
        ):
            raise ConfigError(f"{name}: url must be http(s)")
        if cmd is not None and (
            not isinstance(cmd, list) or not cmd or not all(isinstance(x, str) for x in cmd)
        ):
            raise ConfigError(f"{name}: command must be a non-empty string list")
        bearer = s.get("bearer_env")
        if bearer is not None and (not isinstance(bearer, str) or not ENV_RE.fullmatch(bearer)):
            raise ConfigError(f"{name}: invalid bearer_env")
        if bearer is not None and url is None:
            raise ConfigError(f"{name}: bearer_env needs url")
        oauth = s.get("oauth_env")
        if oauth is not None and (not isinstance(oauth, str) or not ENV_RE.fullmatch(oauth)):
            raise ConfigError(f"{name}: invalid oauth_env")
        if oauth is not None and (bearer is not None or not (url or "").startswith("https://")):
            raise ConfigError(f"{name}: oauth_env needs an https url and no bearer_env")
        tools = s.get("tools")
        if tools is not None and (
            not isinstance(tools, list)
            or not tools
            or not all(isinstance(t, str) and TOOL_RE.fullmatch(t) for t in tools)
        ):
            raise ConfigError(f"{name}: tools must be a non-empty list of tool names")
        out[name] = {"url": url, "command": cmd, "bearer_env": bearer, "tools": tools,
                     "oauth_env": oauth}  # fmt: skip
    if problem := namespace_problem(list(out)):
        raise ConfigError(problem)
    return out


def namespace_problem(names: list[str]) -> str | None:
    """`a` + tool `b_c` and `a_b` + tool `c` both give `a_b_c`: refuse a server
    name that starts with another server name + '_'."""
    for a in names:
        for b in names:
            if a != b and b.startswith(a + "_"):
                return f"server names {a!r} and {b!r} clash in the '<server>_<tool>' namespace"
    return None


class Policy:
    """Which namespaced tool names are allowed (tools=None: all of that server)."""

    def __init__(self, servers: dict[str, dict]):
        self.servers = servers

    def resolve(self, name: str) -> tuple[str | None, str | None, bool]:
        """(server, tool, allowed) for a namespaced tool name."""
        for s, cfg in self.servers.items():
            if name.startswith(s + "_") and len(name) > len(s) + 1:
                tool = name[len(s) + 1 :]
                allowed = cfg["tools"] is None or tool in cfg["tools"]
                return s, tool, allowed
        return None, None, False


def args_sha256(args: Any) -> str:
    raw = json.dumps(args if args is not None else {}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


LOG_MAX = 10 * 1024 * 1024  # calls.jsonl rotates at 10 MB; one old file kept
NAME_MAX = 128  # agent-chosen tool names are truncated in the log
_CTRL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f-\x9f]")


def no_ctrl(s: str) -> str:
    """Visible \\xNN for C0 (except tab), DEL and C1 controls: reasons are
    shown in the host terminal and may carry upstream-chosen text."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", s)


class CallLog:
    def __init__(self, path: str | Path | None, max_bytes: int = LOG_MAX):
        self.path = Path(path) if path else None
        self.max_bytes = max_bytes

    def write(self, **rec: Any) -> None:
        line = json.dumps(
            {"time": datetime.now(UTC).isoformat(timespec="milliseconds"), **rec},
            separators=(",", ":"),
        )
        if self.path is None:
            print(line, file=sys.stderr, flush=True)
            return
        try:
            if self.path.stat().st_size >= self.max_bytes:
                os.replace(self.path, self.path.with_name(self.path.name + ".1"))
        except FileNotFoundError:
            pass
        with self.path.open("a") as f:
            f.write(line + "\n")


def _middleware(policy: Policy, log: CallLog):
    from fastmcp.exceptions import PromptError, ResourceError, ToolError
    from fastmcp.server.middleware import Middleware

    class Gate(Middleware):
        async def on_list_tools(self, context, call_next):
            tools = await call_next(context)
            return [t for t in tools if policy.resolve(t.name)[2]]

        async def on_call_tool(self, context, call_next):
            name = context.message.name
            args = context.message.arguments
            server, tool, allowed = policy.resolve(name)
            rec = {"server": server, "tool": (tool if server else name)[:NAME_MAX],
                   "args_sha256": args_sha256(args)}  # fmt: skip
            t0 = time.monotonic()
            if not allowed:
                log.write(**rec, status="denied", duration_ms=0)
                raise ToolError(f"tool {name!r} is not allowed by the agentbox profile")
            status = "error"
            try:
                result = await call_next(context)
                status = "error" if getattr(result, "is_error", False) else "ok"
                return result
            finally:
                ms = round((time.monotonic() - t0) * 1000, 1)
                log.write(**rec, status=status, duration_ms=ms)

        async def on_list_resources(self, context, call_next):
            return []

        async def on_list_resource_templates(self, context, call_next):
            return []

        async def on_list_prompts(self, context, call_next):
            return []

        async def on_read_resource(self, context, call_next):
            raise ResourceError("resources are not exposed by the agentbox gateway")

        async def on_get_prompt(self, context, call_next):
            raise PromptError("prompts are not exposed by the agentbox gateway")

    return Gate()


def stdio_env(env: dict[str, str]) -> dict[str, str]:
    out = {k: env[k] for k in STDIO_ENV if k in env}
    out["HOME"] = STDIO_HOME
    return out


def _no_forward(cls):
    """FastMCP proxies force `TransportOptions(forward_incoming_headers=True)`
    (server/providers/proxy.py PROXY_TRANSPORT_OPTIONS): the agent's request
    headers, including `Authorization: Bearer <MCP_GATEWAY_TOKEN>`, would go
    to every HTTP upstream (seen live: the token reached mcp.deepwiki.com).
    This subclass turns forwarding off, so an upstream gets only its own
    bearer (or no Authorization at all)."""
    from dataclasses import replace

    from fastmcp.client.transports.base import TransportOptions

    class NoForward(cls):
        def connect_session(self, *, transport_options=None, **kw):
            opts = replace(transport_options or TransportOptions(), forward_incoming_headers=False)
            return super().connect_session(transport_options=opts, **kw)

    NoForward.__name__ = f"NoForward{cls.__name__}"
    return NoForward


def relogin_hint(profile: str, server: str) -> str:
    return f"agentbox mcp login {profile} {server}"


def make_stores(servers: dict[str, dict], env: dict[str, str], profile: str,
                state_dir: str | None = None, on_failed=None) -> tuple[dict, dict]:  # fmt: skip
    """TokenStore per OAuth upstream; (stores, problems) where problems maps a
    server to a short reason (not logged in / bad token set)."""
    import upstream_oauth as uo

    stores, problems = {}, {}
    for name, cfg in servers.items():
        if not cfg.get("oauth_env"):
            continue
        hint = relogin_hint(profile, name)
        raw = env.get(cfg["oauth_env"])
        if not raw:
            problems[name] = f"not logged in ({hint})"
            continue
        try:
            stores[name] = uo.TokenStore(name, raw, hint, state_dir or uo.OAUTH_DIR,
                                         on_failed=on_failed)  # fmt: skip
        except uo.TokenSetError as e:
            problems[name] = f"{e}; re-login needed ({hint})"
    return stores, problems


def upstream_transport(cfg: dict, env: dict[str, str], store=None):
    from fastmcp.client.transports import SSETransport, StdioTransport, StreamableHttpTransport

    if cfg["command"] is not None:
        os.makedirs(STDIO_HOME, exist_ok=True)
        cmd = cfg["command"]
        return StdioTransport(command=cmd[0], args=cmd[1:], env=stdio_env(env), cwd=STDIO_HOME)
    auth = None
    if cfg.get("oauth_env"):
        if store is None:
            raise ConfigError("OAuth token set was not delivered")
        import upstream_oauth as uo

        auth = uo.make_auth(store)
    if cfg["bearer_env"]:
        auth = env.get(cfg["bearer_env"])
        if not auth:
            raise ConfigError(f"bearer secret {cfg['bearer_env']} was not delivered")
    url = cfg["url"]
    path = url.split("?", 1)[0].rstrip("/")
    cls = SSETransport if path.endswith("/sse") else StreamableHttpTransport
    return _no_forward(cls)(url, auth=auth)


def build(
    servers: dict[str, dict],
    token: str,
    env: dict[str, str],
    log: CallLog,
    targets: dict[str, Any] | None = None,
    stores: dict | None = None,
):
    """The gateway FastMCP server. `targets` (tests) maps a server name to a
    proxy target (a FastMCP instance) instead of a transport from its config."""
    from fastmcp import Client, FastMCP
    from fastmcp.server import create_proxy
    from fastmcp.server.auth.providers.jwt import StaticTokenVerifier

    if not token:
        raise ConfigError(f"{TOKEN_ENV} is empty")
    auth = StaticTokenVerifier(tokens={token: {"client_id": "agent", "scopes": []}})
    policy = Policy(servers)
    main = FastMCP("agentbox", auth=auth, middleware=[_middleware(policy, log)])
    stores = stores or {}
    for name, cfg in servers.items():
        target = (targets or {}).get(name)
        if target is None:
            if cfg.get("oauth_env") and name not in stores:
                continue  # not logged in: no tools (status and doctor say why)
            target = Client(upstream_transport(cfg, env, stores.get(name)))
        proxy = create_proxy(target, name=f"upstream-{name}")
        if cfg["tools"] is None:
            proxy.enable(components={"tool"}, only=True)
        else:
            proxy.enable(names=set(cfg["tools"]), components={"tool"}, only=True)
        main.mount(proxy, namespace=name)
    return main


def take_env(env: dict[str, str], names: list[str]) -> dict[str, str]:
    """Remove the secret names from `env` (so no child process inherits them)."""
    return {n: env.pop(n) for n in names if n in env}


def short_reason(e: BaseException, secrets: list[str]) -> str:
    """One line, no secret values: exception type + message (innermost cause)."""

    def leaf(x: BaseException) -> BaseException:
        """Innermost non-group cause (cause chains, groups, contexts; no cycles)."""
        seen: set[int] = set()
        best = x
        while id(x) not in seen:
            seen.add(id(x))
            if not isinstance(x, BaseExceptionGroup):
                best = x
            if x.__cause__ is not None:
                x = x.__cause__
            elif isinstance(x, BaseExceptionGroup) and x.exceptions:
                x = x.exceptions[0]
            elif x.__context__ is not None:
                x = x.__context__
            else:
                break
        return best

    inner = leaf(e)
    msg = f"{type(e).__name__}: {e}"
    if inner is not e and str(inner) not in msg:
        msg += f" (cause {type(inner).__name__}: {inner})"
    for v in secrets:
        if v:
            msg = msg.replace(v, "<redacted>")
    return no_ctrl(" ".join(msg.split()))[:200]


def find_exc(e: BaseException, cls) -> BaseException | None:
    """The first `cls` in e's cause/context chain or exception groups."""
    seen: set[int] = set()
    todo = [e]
    while todo:
        x = todo.pop()
        if x is None or id(x) in seen:
            continue
        seen.add(id(x))
        if isinstance(x, cls):
            return x
        todo += [x.__cause__, x.__context__]
        if isinstance(x, BaseExceptionGroup):
            todo += list(x.exceptions)
    return None


async def probe_one(name: str, cfg: dict, env: dict[str, str], timeout: float,
                    store=None, problem: str | None = None) -> dict:  # fmt: skip
    """Connect to one upstream with a fresh client and list its tools."""
    import asyncio

    from fastmcp import Client

    if problem:
        return {"state": "failed", "reason": problem}
    secrets = [env.get(cfg["bearer_env"] or "", ""), env.get(cfg.get("oauth_env") or "", "")]
    if store is not None:
        import upstream_oauth as uo

        secrets += store.secrets()
    try:
        async with asyncio.timeout(timeout):
            async with Client(upstream_transport(cfg, env, store)) as c:
                tools = [t.name for t in await c.list_tools()]
    except BaseException as e:  # noqa: BLE001 (report every failure, incl. groups/timeouts)
        if isinstance(e, KeyboardInterrupt | SystemExit):
            raise
        if store is not None and (x := find_exc(e, uo.ReloginNeeded)) is not None:
            return {"state": "failed", "reason": f"re-login needed ({x})"}
        if store is not None and (x := find_exc(e, uo.RefreshError)) is not None:
            return {"state": "failed", "reason": no_ctrl(f"token refresh failed: {x}")[:200]}
        reason = "timeout" if isinstance(e, TimeoutError) else short_reason(e, secrets)
        return {"state": "failed", "reason": reason}
    missing = sorted(set(cfg["tools"] or []) - set(tools))
    return {"state": "connected", "tools": len(tools), "missing_allowed": missing}


async def probe(servers: dict[str, dict], env: dict[str, str], timeout: float,
                stores: dict | None = None, problems: dict | None = None) -> dict:  # fmt: skip
    import asyncio

    names = list(servers)
    stores, problems = stores or {}, problems or {}
    res = await asyncio.gather(*(probe_one(n, servers[n], env, timeout, stores.get(n),
                                           problems.get(n)) for n in names))  # fmt: skip
    return {
        "time": datetime.now(UTC).isoformat(timespec="seconds"),
        "servers": dict(zip(names, res, strict=True)),
    }


def write_status(path: str | Path, status: dict) -> None:
    p = Path(path)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(status, indent=1, sort_keys=True) + "\n")
    tmp.replace(p)


def secrets_from_dir(names: list[str], d: str = SECRETS_DIR) -> dict[str, str]:
    out = {}
    for n in names:
        f = Path(d) / n
        if f.is_file():
            out[n] = f.read_text().rstrip("\n")
    return out


def load(cfg_path: str) -> dict[str, dict]:
    return load_config(json.loads(Path(cfg_path).read_text()))


def load_profile_name(cfg_path: str) -> str:
    try:
        return str(json.loads(Path(cfg_path).read_text()).get("profile") or "<profile>")
    except (OSError, ValueError, AttributeError):
        return "<profile>"


def secret_names(servers: dict[str, dict]) -> list[str]:
    return [n for s in servers.values() for n in (s["bearer_env"], s.get("oauth_env")) if n]


def exec_env(cfg_path: str):
    """(servers, env, stores, problems) for an exec'd subcommand: secrets come
    from /run/secrets (an exec session lacks the entrypoint's env)."""
    servers = load(cfg_path)
    env = {**os.environ, **secrets_from_dir(secret_names(servers))}
    stores, problems = make_stores(servers, env, load_profile_name(cfg_path))
    return servers, env, stores, problems


def main_oauth_status() -> int:
    """`gateway.py oauth-status`: per OAuth upstream, names and times only."""
    cfg_path = os.environ.get("MCP_GATEWAY_CONFIG", CONFIG)
    servers, _env, stores, problems = exec_env(cfg_path)
    out = {}
    for name, cfg in servers.items():
        if not cfg.get("oauth_env"):
            continue
        if name in problems:
            out[name] = {"state": "needs_login", "reason": problems[name]}
        else:
            try:
                out[name] = stores[name].status()
            except OSError as e:
                out[name] = {"state": "error", "reason": type(e).__name__}
    print(json.dumps({"servers": out}))
    return 0


def main_oauth_logout(name: str) -> int:
    """`gateway.py oauth-logout <server>`: best-effort revocation of the
    current refresh and access token, then delete the volume copy."""
    import upstream_oauth as uo

    cfg_path = os.environ.get("MCP_GATEWAY_CONFIG", CONFIG)
    try:
        _servers, _env, stores, _problems = exec_env(cfg_path)
    except (OSError, ValueError, ConfigError):
        stores = {}
    current = None
    if name in stores:
        revoked, current = stores[name].logout()
        removed = True
    else:
        revoked = "no token set here"
        current = uo.remove_volume_copy(name) if NAME_RE.fullmatch(name) else None
        removed = current is not None
    # `current` (tokens) goes only to the host CLI over the exec pipe, which
    # revokes it itself when this revocation failed; never logged.
    print(json.dumps({"server": name, "revoked": revoked, "removed": removed,
                      "current": current}))  # fmt: skip
    return 0


def status_patcher(path: str):
    """on_failed callback of the serving process: mark the upstream failed in
    status.json right away (the next probe says the same)."""
    import threading

    lock = threading.Lock()

    def patch(name: str, reason: str) -> None:
        with lock:
            try:
                st = json.loads(Path(path).read_text())
            except (OSError, ValueError):
                st = {"servers": {}}
            st.setdefault("servers", {})[name] = {"state": "failed", "reason": reason}
            st["time"] = datetime.now(UTC).isoformat(timespec="seconds")
            write_status(path, st)

    return patch


def main_probe() -> int:
    """`gateway.py probe`: refresh the upstream status (run by `agentbox up`
    and doctor via `docker compose exec`). Bearers come from /run/secrets:
    an exec session does not have the entrypoint's exported env."""
    import asyncio

    servers, env, stores, problems = exec_env(os.environ.get("MCP_GATEWAY_CONFIG", CONFIG))
    timeout = float(os.environ.get("MCP_PROBE_TIMEOUT", PROBE_TIMEOUT))
    status = asyncio.run(probe(servers, env, timeout, stores, problems))
    write_status(os.environ.get("MCP_GATEWAY_STATUS", STATUS_FILE), status)
    print(json.dumps(status))
    return 0


def startup_probe(servers: dict[str, dict], env: dict[str, str], stores=None,
                  problems=None) -> None:  # fmt: skip
    """Status at startup, in a background thread with its own event loop and
    its own transports (nothing shared with the serving loop)."""
    import asyncio
    import threading

    def run():
        try:
            write_status(os.environ.get("MCP_GATEWAY_STATUS", STATUS_FILE),
                         asyncio.run(probe(servers, env, PROBE_TIMEOUT, stores,
                                           problems)))  # fmt: skip
        except Exception as e:  # noqa: BLE001
            print(f"mcp-gateway: startup probe failed: {type(e).__name__}", file=sys.stderr)

    threading.Thread(target=run, daemon=True, name="startup-probe").start()


def main() -> int:
    if sys.argv[1:] == ["probe"]:
        return main_probe()
    if sys.argv[1:] == ["oauth-status"]:
        return main_oauth_status()
    if len(sys.argv) == 3 and sys.argv[1] == "oauth-logout":
        return main_oauth_logout(sys.argv[2])
    cfg_path = os.environ.get("MCP_GATEWAY_CONFIG", CONFIG)
    try:
        servers = load(cfg_path)
    except (OSError, ValueError, ConfigError) as e:
        print(f"mcp-gateway: config {cfg_path}: {e}", file=sys.stderr)
        return 2
    secrets = take_env(os.environ, [TOKEN_ENV, *secret_names(servers)])
    env = {**os.environ, **secrets}
    log_path = os.environ.get("MCP_GATEWAY_LOG", LOG_FILE)
    status_path = os.environ.get("MCP_GATEWAY_STATUS", STATUS_FILE)
    stores, problems = make_stores(servers, env, load_profile_name(cfg_path),
                                   on_failed=status_patcher(status_path))  # fmt: skip
    try:
        server = build(servers, secrets.get(TOKEN_ENV, ""), env, CallLog(log_path),
                       stores=stores)  # fmt: skip
    except ConfigError as e:
        print(f"mcp-gateway: {e}", file=sys.stderr)
        return 2
    print(f"mcp-gateway: {len(servers)} server(s): {', '.join(servers) or 'none'}",
          file=sys.stderr, flush=True)  # fmt: skip
    startup_probe(servers, env, stores, problems)
    server.run(transport="http", host="0.0.0.0", port=PORT, path=PATH, show_banner=False)
    return 0


if __name__ == "__main__":
    sys.exit(main())
