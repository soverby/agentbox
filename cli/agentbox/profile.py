"""Profile schema: load, validate, resolve defaults (PLAN §2.3–§2.6).

Host-side mount checks (realpath, existence, denylist) are P3; see `check_mount_host`.
Every pattern check uses `re.fullmatch`, so a trailing newline never passes.
"""

from __future__ import annotations

import ipaddress
import math
import os
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

PROFILE_NAME_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,30}")
SECRET_NAME_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
ITEM_NAME_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]*")
LABEL_RE = re.compile(r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?")
MEMORY_RE = re.compile(r"([1-9][0-9]*)([kmg])", re.I)
PACKAGE_RE = re.compile(r"[a-z0-9][a-z0-9+.-]*")
URL_RE = re.compile(r"https?://[^/\s?#@]+(/[^\s]*)?")  # no userinfo
OLLAMA_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*(:[a-zA-Z0-9._-]+)?")
TOOL_RE = re.compile(r"[A-Za-z0-9_.-]{1,128}")
CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
REF_RES = (
    re.compile(r"keychain:\S+"),
    re.compile(r"op://[^/\s]+/[^/\s]+/[^/\s]+"),
    re.compile(r"env:[A-Za-z_][A-Za-z0-9_]*"),
)
RESERVED_SECRET_RE = re.compile(
    r"MCP_GATEWAY_TOKEN|AGENTBOX_.*|PATH|HOME|USER|SHELL|LD_.*|NODE_OPTIONS|PYTHON.*"
    r"|ANTHROPIC_BASE_URL|ANTHROPIC_AUTH_TOKEN|OLLAMA_HOST|DISABLE_AUTOUPDATER|DISABLE_UPDATES"
    r"|ENABLE_CLAUDEAI_MCP_SERVERS|CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC"
)
PROXY_SECRET_RE = re.compile(r".*_PROXY|NPM_CONFIG_.*", re.I)
LOCAL_SUFFIXES = ("localhost", "localdomain", "local", "internal", "home.arpa")
RESERVED_ROOTS = (
    "/usr", "/etc", "/bin", "/sbin", "/opt", "/proc", "/sys", "/dev",
    "/run", "/var", "/tmp", "/home/agent", "/root", "/boot",
)  # fmt: skip
MIN_MEMORY = 64 * 1024**2

AGENTS = ("claude", "codex", "pi")
NETWORK_MODES = ("strict", "open")
MOUNT_MODES = ("ro", "rw")
TARGETS = ("agent", "router", "mcp-gateway")
DEFAULT_PRESETS = ["anthropic", "openai", "github", "dev"]
CLAUDE_TOKEN = "CLAUDE_CODE_OAUTH_TOKEN"


class ProfileError(Exception):
    """All problems found in one profile. Each problem is (key path, message)."""

    def __init__(self, problems: list[tuple[str, str]]):
        self.problems = problems
        super().__init__("\n".join(f"{p}: {m}" for p, m in problems))


@dataclass(frozen=True)
class Resources:
    cpus: float | None = None
    memory: str | None = None


@dataclass(frozen=True)
class Box:
    agents: list[str]
    resources: Resources
    packages: list[str]
    web_tools: bool
    skip_permissions: bool


@dataclass(frozen=True)
class Mount:
    host: str  # as written in the profile
    path: str  # container path, normalised
    mode: str
    allow_dotpath: bool


@dataclass(frozen=True)
class Network:
    mode: str
    presets: list[str]
    allow: list[str]  # lowercased, deduplicated
    allow_http: bool


@dataclass(frozen=True)
class Secret:
    name: str
    ref: str
    to: list[str]  # sorted target containers


@dataclass(frozen=True)
class RemoteModel:
    name: str
    api_base: str
    key: str | None


@dataclass(frozen=True)
class Models:
    ollama: str | list[str]
    remote: dict[str, RemoteModel]


@dataclass(frozen=True)
class McpServer:
    name: str
    url: str | None
    command: list[str] | None
    bearer: str | None
    auth: str | None
    tools: list[str] | None


@dataclass(frozen=True)
class Profile:
    name: str
    box: Box
    mounts: list[Mount]
    network: Network
    secrets: dict[str, Secret]
    models: Models
    mcp_servers: dict[str, McpServer] = field(default_factory=dict)


def check_mount_host(host: str) -> None:
    """P3 hook: realpath, existence, and denylist checks (PLAN §2.3 T1).

    Not implemented in P0. P0 only expands `~`.
    """


def full(pattern: re.Pattern, s: str) -> bool:
    return pattern.fullmatch(s) is not None


def hostname_problem(entry: str) -> str | None:
    """Why `entry` is not a valid allowlist hostname, or None when it is valid.

    Valid: a DNS name, optionally with a leading '.' (squid: this domain and
    all subdomains). Input is compared lowercased.
    """
    if not entry.isascii():
        return "non-ASCII name: use punycode (xn--…)"
    name = entry.lower()
    name = name[1:] if name.startswith(".") else name
    try:
        ipaddress.ip_address(name.strip("[]"))
        return "IP addresses are not allowed"
    except ValueError:
        pass
    labels = name.split(".")
    if len(name) > 253 or len(labels) < 2 or not all(full(LABEL_RE, x) for x in labels):
        return (
            "must be a hostname with at least two labels "
            "(no port, scheme, path, or wildcard; a leading '.' matches subdomains)"
        )
    if labels[-1].isdigit() or labels[-1].startswith("0x"):
        return "last label must not be numeric"
    for suffix in LOCAL_SUFFIXES:
        if name == suffix or name.endswith("." + suffix):
            return f"local names (*.{suffix}) are not allowed"
    return None


def merge_domains(*lists: list[str]) -> list[str]:
    """Lowercase and dedupe allowlist entries, keeping first-seen order.

    Drops `a.b` and `.x.a.b` when `.a.b` is present (squid rejects overlaps).
    """
    seen: list[str] = []
    for lst in lists:
        for h in lst:
            h = h.lower()
            if h not in seen:
                seen.append(h)
    wild = {h for h in seen if h.startswith(".")}

    def covered(h: str) -> bool:
        bare = h.lstrip(".")
        return any(w != h and (("." + bare) == w or ("." + bare).endswith(w)) for w in wild)

    return [h for h in seen if not covered(h)]


def secret_name_problem(name: str, as_ref_key: bool = False) -> str | None:
    if not full(SECRET_NAME_RE, name):
        return f"invalid secret name {name!r}"
    if full(RESERVED_SECRET_RE, name) or full(PROXY_SECRET_RE, name):
        return f"{name} is a reserved name"
    if as_ref_key and name == CLAUDE_TOKEN:
        return f"{name} cannot be a model key or MCP bearer"
    return None


def ref_ok(ref: str) -> bool:
    return any(full(r, ref) for r in REF_RES)


def normalize_container_path(path: str) -> str:
    # normpath keeps a leading "//" (POSIX allows it); collapse all slash runs first.
    return posixpath.normpath(re.sub(r"/+", "/", path))


def container_path_problem(path: str) -> str | None:
    if not path.startswith("/"):
        return f"container path must be absolute, got {path!r}"
    if ".." in path.split("/"):
        return "container path must not contain '..'"
    if ":" in path or "," in path or "\n" in path:
        return "container path must not contain ':', ',' or newline"
    norm = normalize_container_path(path)
    first = norm.split("/")[1] if norm != "/" else ""
    hint = "; set `path` to mount it elsewhere"
    if norm in ("/", "/home") or first.startswith("lib"):
        return f"container path {norm} is reserved{hint}"
    for root in RESERVED_ROOTS:
        if norm == root or norm.startswith(root + "/"):
            return f"container path {norm} is under reserved {root}{hint}"
    return None


def memory_bytes(s: str) -> int | None:
    m = MEMORY_RE.fullmatch(s)
    if not m:
        return None
    return int(m.group(1)) * 1024 ** "kmg".index(m.group(2).lower()) * 1024


class _V:
    """Collects problems while reading a parsed TOML document."""

    def __init__(self) -> None:
        self.problems: list[tuple[str, str]] = []

    def err(self, path: str, msg: str) -> None:
        self.problems.append((path, msg))

    def table(self, value: Any, path: str, allowed: set[str] | None) -> dict:
        """Check `value` is a table; if `allowed` is given, reject other keys."""
        if not isinstance(value, dict):
            self.err(path, "must be a table")
            return {}
        for k in value if allowed is not None else ():
            if k not in allowed:
                self.err(f"{path}.{k}" if path else k, "unknown key")
        return value

    def typed(self, d: dict, key: str, path: str, types: tuple, default: Any, tname: str) -> Any:
        if key not in d:
            return default
        v = d[key]
        # bool is a subclass of int; reject it where a number is expected
        if not isinstance(v, types) or (isinstance(v, bool) and bool not in types):
            self.err(f"{path}.{key}", f"must be {tname}")
            return default
        if isinstance(v, str) and CONTROL_RE.search(v):
            self.err(f"{path}.{key}", "must not contain control characters")
            return default
        return v

    def str_list(self, d: dict, key: str, path: str, default: Any, pattern=None) -> Any:
        v = self.typed(d, key, path, (list,), default, "a list of strings")
        if v is default:
            return default
        out = []
        for i, item in enumerate(v):
            p = f"{path}.{key}[{i}]"
            if not isinstance(item, str):
                self.err(p, "must be a string")
            elif not item:
                self.err(p, "must not be empty")
            elif CONTROL_RE.search(item):
                self.err(p, "must not contain control characters")
            elif pattern is not None and not full(pattern, item):
                self.err(p, f"invalid value {item!r}")
            else:
                out.append(item)
        return out

    def enum(self, d: dict, key: str, path: str, allowed: tuple, default: str | None) -> Any:
        v = self.typed(d, key, path, (str,), default, "a string")
        if v is not None and v not in allowed:
            self.err(f"{path}.{key}", f"must be one of {', '.join(allowed)}")
            return default
        return v

    def url(self, d: dict, key: str, path: str) -> str | None:
        u = self.typed(d, key, path, (str,), None, "a string")
        if u is not None and not full(URL_RE, u):
            self.err(f"{path}.{key}", "must be an http(s) URL")
        return u

    def secret_ref(self, d: dict, key: str, path: str) -> str | None:
        name = self.typed(d, key, path, (str,), None, "a string")
        if name is not None and (msg := secret_name_problem(name, as_ref_key=True)):
            self.err(f"{path}.{key}", msg)
            return None
        return name


def _default_ref(profile: str, name: str, shared: bool) -> str:
    scope = "_shared" if shared else profile
    return f"keychain:agentbox/{scope}/{name}"


def _parse_box(v: _V, top: dict) -> Box:
    keys = {"agents", "resources", "packages", "web_tools", "skip_permissions"}
    b = v.table(top.get("box", {}), "box", keys)
    agents = v.str_list(b, "agents", "box", list(AGENTS))
    for i, a in enumerate(agents):
        if a not in AGENTS:
            v.err(f"box.agents[{i}]", f"must be one of {', '.join(AGENTS)}")
    if len(set(agents)) != len(agents):
        v.err("box.agents", "duplicate agent")
    if not agents and "agents" in b:
        v.err("box.agents", "must not be empty")
    r = v.table(b.get("resources", {}), "box.resources", {"cpus", "memory"})
    cpus = v.typed(r, "cpus", "box.resources", (int, float), None, "a number")
    if cpus is not None and (not math.isfinite(cpus) or cpus <= 0):
        v.err("box.resources.cpus", "must be a finite number > 0")
    memory = v.typed(r, "memory", "box.resources", (str,), None, "a string")
    if memory is not None:
        size = memory_bytes(memory)
        if size is None:
            v.err("box.resources.memory", "must be a size with unit k, m, or g (e.g. 8g)")
        elif size < MIN_MEMORY:
            v.err("box.resources.memory", "must be at least 64m")
    return Box(
        agents=[a for a in agents if a in AGENTS],
        resources=Resources(cpus=cpus, memory=memory),
        packages=v.str_list(b, "packages", "box", [], PACKAGE_RE),
        web_tools=v.typed(b, "web_tools", "box", (bool,), True, "a boolean"),
        skip_permissions=v.typed(b, "skip_permissions", "box", (bool,), True, "a boolean"),
    )


def _parse_mounts(v: _V, top: dict) -> list[Mount]:
    mounts: list[Mount] = []
    raw = top.get("mount", [])
    if not isinstance(raw, list):
        v.err("mount", "must be an array of tables ([[mount]])")
        raw = []
    if not raw:
        v.err("mount", "at least one [[mount]] is required")
    seen: dict[str, int] = {}
    for i, m in enumerate(raw):
        p = f"mount[{i}]"
        m = v.table(m, p, {"host", "path", "mode", "allow_dotpath"})
        host = v.typed(m, "host", p, (str,), None, "a string")
        if host is None:
            if "host" not in m:
                v.err(f"{p}.host", "is required")
            continue
        check_mount_host(host)
        explicit = v.typed(m, "path", p, (str,), None, "a string")
        path, where = (
            (explicit, f"{p}.path")
            if explicit is not None
            else (os.path.expanduser(host), f"{p}.host")
        )
        if msg := container_path_problem(path):
            v.err(where, msg)
            continue
        path = normalize_container_path(path)
        if path in seen:
            v.err(where, f"container path {path} duplicates mount[{seen[path]}]")
        seen[path] = i
        mounts.append(
            Mount(
                host=host,
                path=path,
                mode=v.enum(m, "mode", p, MOUNT_MODES, "ro"),
                allow_dotpath=v.typed(m, "allow_dotpath", p, (bool,), False, "a boolean"),
            )
        )
    return mounts


def _parse_network(v: _V, top: dict) -> Network:
    n = v.table(top.get("network", {}), "network", {"mode", "presets", "allow", "allow_http"})
    allow = v.str_list(n, "allow", "network", [])
    for i, h in enumerate(allow):
        if msg := hostname_problem(h):
            v.err(f"network.allow[{i}]", f"{h!r}: {msg}")
    return Network(
        mode=v.enum(n, "mode", "network", NETWORK_MODES, "strict"),
        presets=v.str_list(n, "presets", "network", list(DEFAULT_PRESETS), ITEM_NAME_RE),
        allow=merge_domains(allow),
        allow_http=v.typed(n, "allow_http", "network", (bool,), False, "a boolean"),
    )


def _parse_models(v: _V, top: dict) -> Models:
    md = v.table(top.get("models", {}), "models", {"ollama", "remote"})
    ollama: Any = md.get("ollama", "local")
    if isinstance(ollama, list):
        ollama = v.str_list(md, "ollama", "models", [], OLLAMA_MODEL_RE)
    elif ollama != "local":
        v.err("models.ollama", 'must be "local" or a list of model names')
        ollama = "local"
    remote: dict[str, RemoteModel] = {}
    for rname, rm in v.table(md.get("remote", {}), "models.remote", None).items():
        p = f"models.remote.{rname}"
        if not full(ITEM_NAME_RE, rname):
            v.err(p, "invalid model name")
        rm = v.table(rm, p, {"api_base", "key"})
        if "api_base" not in rm:
            v.err(f"{p}.api_base", "is required")
        api_base = v.url(rm, "api_base", p)
        remote[rname] = RemoteModel(rname, api_base or "", v.secret_ref(rm, "key", p))
    return Models(ollama=ollama, remote=remote)


def _parse_mcp(v: _V, top: dict) -> dict[str, McpServer]:
    mc = v.table(top.get("mcp", {}), "mcp", {"servers"})
    servers: dict[str, McpServer] = {}
    for sname, s in v.table(mc.get("servers", {}), "mcp.servers", None).items():
        p = f"mcp.servers.{sname}"
        if not full(ITEM_NAME_RE, sname):
            v.err(p, "invalid server name")
        s = v.table(s, p, {"url", "command", "bearer", "auth", "tools"})
        if ("url" in s) == ("command" in s):
            v.err(p, "needs exactly one of url or command")
        url = v.url(s, "url", p)
        command = v.str_list(s, "command", p, None)
        if command is not None and not command:
            v.err(f"{p}.command", "must not be empty")
        bearer = v.secret_ref(s, "bearer", p)
        auth = v.enum(s, "auth", p, ("oauth",), None)
        if "bearer" in s and "auth" in s:
            v.err(p, "bearer and auth are mutually exclusive")
        if "command" in s and ("bearer" in s or "auth" in s):
            v.err(p, "bearer/auth apply only to url servers")
        tools = v.str_list(s, "tools", p, None, TOOL_RE)
        if tools == [] and s.get("tools") == []:
            v.err(f"{p}.tools", "must not be empty; omit `tools` for all tools")
        if tools and len(set(tools)) != len(tools):
            v.err(f"{p}.tools", "duplicate tool")
        servers[sname] = McpServer(sname, url, command, bearer, auth, tools)
    return servers


def _parse_secrets(
    v: _V, top: dict, name: str, box: Box, models: Models, servers: dict[str, McpServer]
) -> dict[str, Secret]:
    inferred: dict[str, set[str]] = {}
    for rm in models.remote.values():
        if rm.key:
            inferred.setdefault(rm.key, set()).add("router")
    for s in servers.values():
        if s.bearer:
            inferred.setdefault(s.bearer, set()).add("mcp-gateway")

    secrets: dict[str, Secret] = {}
    for sname, sv in v.table(top.get("secrets", {}), "secrets", None).items():
        p = f"secrets.{sname}"
        if msg := secret_name_problem(sname):
            v.err(p, msg)
            continue
        explicit: set[str] = set()
        if sv == "shared":  # same as { shared = true, to = "agent" }
            ref = _default_ref(name, sname, shared=True)
            explicit = {"agent"}
        elif isinstance(sv, dict):
            t = v.table(sv, p, {"ref", "to", "shared"})
            shared = v.typed(t, "shared", p, (bool,), False, "a boolean")
            ref = v.typed(t, "ref", p, (str,), None, "a string")
            if ref is not None and shared:
                v.err(p, "ref and shared are mutually exclusive")
            if ref is not None and not ref_ok(ref):
                v.err(f"{p}.ref", "must be keychain:<service>, op://<vault>/<item>/<field>, "
                      "or env:<VAR>")  # fmt: skip
            if ref is None:
                ref = _default_ref(name, sname, shared)
            to = t.get("to")
            to_list = [to] if isinstance(to, str) else to
            if to is not None:
                if not isinstance(to_list, list) or not to_list:
                    v.err(f"{p}.to", "must be a target name or a non-empty list")
                else:
                    for x in to_list:
                        if x not in TARGETS:
                            v.err(f"{p}.to", f"{x!r}: must be one of {', '.join(TARGETS)}")
                        else:
                            explicit.add(x)
        else:
            v.err(p, 'must be "shared" or a table { ref, to, shared }')
            continue
        targets = explicit | inferred.get(sname, set()) or {"agent"}
        if sname == CLAUDE_TOKEN and targets != {"agent"}:
            v.err(p, f"{CLAUDE_TOKEN} must target exactly agent")
        secrets[sname] = Secret(sname, ref, sorted(targets))

    for sname, targets in inferred.items():
        if sname not in secrets:
            secrets[sname] = Secret(sname, _default_ref(name, sname, False), sorted(targets))
    if "claude" in box.agents and CLAUDE_TOKEN not in secrets:
        secrets[CLAUDE_TOKEN] = Secret(
            CLAUDE_TOKEN, _default_ref(name, CLAUDE_TOKEN, True), ["agent"]
        )
    return secrets


def parse_profile(data: dict, name: str) -> Profile:
    """Validate a parsed TOML document and resolve defaults. Raises ProfileError."""
    v = _V()
    if not full(PROFILE_NAME_RE, name):
        v.err("<name>", f"profile name {name!r} must match {PROFILE_NAME_RE.pattern}")
    top = v.table(data, "", {"box", "mount", "network", "secrets", "models", "mcp"})
    box = _parse_box(v, top)
    mounts = _parse_mounts(v, top)
    network = _parse_network(v, top)
    models = _parse_models(v, top)
    servers = _parse_mcp(v, top)
    secrets = _parse_secrets(v, top, name, box, models, servers)
    if v.problems:
        raise ProfileError(v.problems)
    return Profile(name, box, mounts, network, secrets, models, servers)


def load_profile(path: str | Path, name: str | None = None) -> Profile:
    """Load a profile file. The profile name defaults to the file stem."""
    path = Path(path)
    name = name if name is not None else path.stem
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as e:
        raise ProfileError([(str(path), f"invalid TOML: {e}")]) from e
    except UnicodeDecodeError as e:
        raise ProfileError([(str(path), f"not valid UTF-8 (byte {e.start})")]) from e
    except OSError as e:
        raise ProfileError([(str(path), f"cannot read: {e.strerror}")]) from e
    return parse_profile(data, name)
