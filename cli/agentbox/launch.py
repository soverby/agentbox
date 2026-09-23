"""Agent launch argv, working dir mapping, profile resolution (PLAN §2.3).

Pure functions: no Docker calls.
"""

from __future__ import annotations

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from .profile import OLLAMA_MODEL_RE, Profile, ProfileError, load_profile

WITH_SECRETS = "/usr/local/bin/with-secrets"
# The gateway entry for Codex (PLAN §2.6): launch overrides, so T5 does not
# depend on the agent-writable ~/.codex/config.toml (a hostile `command` there
# makes Codex refuse to start: fails closed). Same values as mcpgw.CODEX_MCP.
CODEX_MCP_OVERRIDES = (
    "-c", 'mcp_servers.agentbox.url="http://mcp-gateway:8080/mcp"',
    "-c", 'mcp_servers.agentbox.bearer_token_env_var="MCP_GATEWAY_TOKEN"',
    "-c", "mcp_servers.agentbox.enabled=true",
)  # fmt: skip
CODEX_OVERRIDES = (
    "-c", "features.apps=false",
    "-c", "features.remote_plugin=false",
    "-c", "apps._default.enabled=false",
    *CODEX_MCP_OVERRIDES,
)  # fmt: skip


class ResolveError(Exception):
    pass


# --- model routing (PLAN §2.5): `--model ollama/<m>` | `remote/<name>` | native
GATE_URL = "http://ollama-gate:11434"
ROUTER_URL = "http://router:4000"
ROUTER_KEY_ENV = "AGENTBOX_ROUTER_MASTER_KEY"
CLAUDE_TOKEN_ENV = "CLAUDE_CODE_OAUTH_TOKEN"
NATIVE_MODEL_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,199}")
CODEX_PROVIDER = {"ollama": "agentbox_ollama", "remote": "agentbox_router"}
PI_PROVIDER = {"ollama": "agentbox-ollama", "remote": "agentbox-router"}
# Claude on a model route: the subscription token must never reach ollama-gate
# or the router, so the shim unsets it. The router key goes to
# ANTHROPIC_AUTH_TOKEN by name (after with-secrets), never through argv.
CLAUDE_SHIM = {
    "ollama": 'unset CLAUDE_CODE_OAUTH_TOKEN; exec "$@"',
    "remote": (
        '[ -n "${AGENTBOX_ROUTER_MASTER_KEY-}" ] || '
        "{ echo 'agentbox: no router key in this box (run `agentbox up`)' >&2; exit 1; }; "
        "ANTHROPIC_AUTH_TOKEN=$AGENTBOX_ROUTER_MASTER_KEY; export ANTHROPIC_AUTH_TOKEN; "
        'unset CLAUDE_CODE_OAUTH_TOKEN; exec "$@"'
    ),
}
SHIM_NAME = "agentbox-model"
CLAUDE_MODEL_ENVS = (
    "ANTHROPIC_DEFAULT_HAIKU_MODEL",
    "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL",
    "CLAUDE_CODE_SUBAGENT_MODEL",
)


@dataclass(frozen=True)
class ModelRoute:
    kind: str  # "ollama" | "remote" | "native"
    model: str


@dataclass
class Launch:
    argv: list[str]  # command after with-secrets
    env: dict[str, str] = field(default_factory=dict)  # `docker compose exec -e` (no secrets)


def is_cloud_model(name: str) -> bool:
    """Same rule as ollama-gate: `:cloud` or `:<tag>-cloud` (any case)."""
    tag = name.rpartition(":")[2].lower() if ":" in name else ""
    return tag == "cloud" or tag.endswith("-cloud")


def parse_model(profile: Profile, spec: str | None) -> ModelRoute | None:
    """`--model` value -> route. A missing remote name is a hard error."""
    if spec is None:
        return None
    kind, sep, rest = spec.partition("/")
    if sep and kind == "ollama":
        if not OLLAMA_MODEL_RE.fullmatch(rest):
            raise ResolveError(f"--model {spec!r}: invalid Ollama model name")
        if is_cloud_model(rest):
            raise ResolveError(f"--model {spec!r}: cloud models are never allowed (ollama-gate)")
        allowed = profile.models.ollama
        if allowed != "local":
            names = {n if ":" in n else n + ":latest" for n in allowed}
            if (rest if ":" in rest else rest + ":latest") not in names:
                raise ResolveError(
                    f"--model {spec!r}: not in [models] ollama of {profile.name} "
                    f"({', '.join(allowed) or 'empty'})"
                )
        return ModelRoute("ollama", rest)
    if sep and kind == "remote":
        if rest not in profile.models.remote:
            have = ", ".join(sorted(profile.models.remote)) or "none"
            raise ResolveError(
                f"--model {spec!r}: no [models.remote.{rest}] in profile {profile.name} "
                f"(remote models: {have})"
            )
        return ModelRoute("remote", rest)
    if not NATIVE_MODEL_RE.fullmatch(spec):
        raise ResolveError(f"--model {spec!r}: invalid model name")
    return ModelRoute("native", spec)


def _toml_str(v: str) -> str:
    return json.dumps(v)  # model names hold no quote, backslash, or control char


def codex_model_overrides(route: ModelRoute) -> list[str]:
    """Codex `-c` overrides for a model route (no config file is written)."""
    if route.kind == "native":
        return ["--model", route.model]
    pid = CODEX_PROVIDER[route.kind]
    pre = f"model_providers.{pid}"
    if route.kind == "ollama":
        name, base = "agentbox ollama", f"{GATE_URL}/v1"
    else:
        name, base = "agentbox router", f"{ROUTER_URL}/v1"
    out = [
        "-c", f"model_provider={_toml_str(pid)}",
        "-c", f"{pre}.name={_toml_str(name)}",
        "-c", f"{pre}.base_url={_toml_str(base)}",
        "-c", f'{pre}.wire_api="responses"',
    ]  # fmt: skip
    if route.kind == "remote":
        out += ["-c", f"{pre}.env_key={_toml_str(ROUTER_KEY_ENV)}"]
    return out + ["-c", f"model={_toml_str(route.model)}"]


def agent_launch(
    profile: Profile,
    agent: str,
    args: list[str],
    headless: bool = False,
    model: ModelRoute | None = None,
) -> Launch:
    """Launch for an agent session: argv after with-secrets + exec env.
    No secret value is ever in either: keys move by env var name only."""
    argv = agent_argv(profile, agent, [], headless)
    env: dict[str, str] = {}
    pre: list[str] = []
    extra: list[str] = []
    if model is None:
        pass
    elif agent == "codex":
        # after the fixed overrides, before the bypass flag and exec's `-`
        i = argv.index("--dangerously-bypass-approvals-and-sandbox")
        argv = argv[:i] + codex_model_overrides(model) + argv[i:]
    elif model.kind == "native":
        extra = ["--model", model.model]
    elif agent == "claude":
        m = model.model
        env["ANTHROPIC_BASE_URL"] = GATE_URL if model.kind == "ollama" else ROUTER_URL
        if model.kind == "ollama":
            env["ANTHROPIC_AUTH_TOKEN"] = "ollama"  # Ollama ignores it; not a secret
        # Background and subagent calls use the same model (a claude-* name
        # is refused by the gate and unknown to the router).
        for k in CLAUDE_MODEL_ENVS:
            env[k] = m
        pre = ["sh", "-c", CLAUDE_SHIM[model.kind], SHIM_NAME]
        extra = ["--model", m]
    elif agent == "pi":
        # The root-owned extension in the image (/usr/local/lib/agentbox/
        # pi-models.ts, loaded by the pi wrapper) registers the provider with
        # fixed endpoints; only the route kind and model id come from env.
        env["AGENTBOX_MODEL_ROUTE"] = model.kind
        env["AGENTBOX_MODEL_ID"] = model.model
        extra = ["--provider", PI_PROVIDER[model.kind], "--model", model.model]
    if headless and agent == "codex":  # `codex exec … -`: `-` stays last
        return Launch(pre + argv[:-1] + list(args) + ["-"], env)
    return Launch(pre + argv + extra + list(args), env)


def agent_argv(profile: Profile, agent: str, args: list[str], headless: bool = False):
    """argv for an agent inside the box (without with-secrets).

    headless: `run` mode (`claude -p`, `codex exec --skip-git-repo-check -`, `pi -p`).
    The prompt is never in argv: it goes on stdin (no option parsing of prompt
    text, no argv size limit). Verified against the image: `claude -p` and
    `codex exec -` read stdin; Pi prepends piped stdin to the prompt.
    """
    box = profile.box
    if agent not in box.agents:
        raise ResolveError(f"agent {agent!r} is not in [box] agents of {profile.name}")
    if agent == "claude":
        argv = ["claude"]
        if box.skip_permissions:
            argv.append("--dangerously-skip-permissions")
        if not box.web_tools:
            argv += ["--disallowedTools", "WebFetch", "WebSearch"]
        if headless:
            argv.append("-p")
    elif agent == "codex":
        argv = ["codex"]
        if headless:
            argv.append("exec")
        argv += [*CODEX_OVERRIDES, "--dangerously-bypass-approvals-and-sandbox"]
        if not box.web_tools:
            argv += ["-c", "web_search=disabled"]
        if headless:
            argv += ["--skip-git-repo-check", "-"]
    elif agent == "pi":
        argv = ["pi"]
        if headless:
            argv.append("-p")
    else:
        raise ResolveError(f"unknown agent {agent!r}")
    return argv + list(args)


def _norm(p: str, ci: bool) -> str:
    return p.casefold() if ci else p


def mount_for(profile: Profile, host_dir: str, ci: bool | None = None):
    """(mount, relative parts) for the deepest mount containing host_dir, or None."""
    ci = sys.platform == "darwin" if ci is None else ci
    real = os.path.realpath(host_dir)
    best = None
    for m in profile.mounts:
        root = m.host_real or os.path.realpath(os.path.expanduser(m.host))
        r, c = _norm(root.rstrip("/") or "/", ci), _norm(real, ci)
        if c == r or c.startswith(r.rstrip("/") + "/"):
            rel = real[len(root.rstrip("/")) :].lstrip("/")
            if best is None or len(root) > len(best[2]):
                best = (m, rel, root)
    return None if best is None else best[:2]


def container_workdir(profile: Profile, host_dir: str, ci: bool | None = None) -> str:
    """Container dir for host_dir if it is inside a mount, else the first mount."""
    hit = mount_for(profile, host_dir, ci)
    if hit is None:
        return profile.mounts[0].path
    m, rel = hit
    return m.path if not rel else m.path.rstrip("/") + "/" + rel


def exec_argv(
    project: str,
    compose_file: str,
    workdir: str,
    cmd: list[str],
    tty: bool,
    env: dict[str, str] | None = None,
):
    """`docker compose exec` through with-secrets. Never a login shell.
    `env`: non-secret exec env (`-e`); values are visible in host `ps`."""
    argv = ["docker", "compose", "-p", project, "-f", compose_file, "exec"]
    if not tty:
        argv.append("-T")
    for k, v in (env or {}).items():
        argv += ["-e", f"{k}={v}"]
    return [*argv, "-w", workdir, "agent", WITH_SECRETS, *cmd]


def list_profiles(pdir: Path) -> list[str]:
    return sorted(p.stem for p in pdir.glob("*.toml")) if pdir.is_dir() else []


def resolve_profile(pdir: Path, cwd: str, ci: bool | None = None) -> str:
    """Profile whose mount contains cwd. Error lists candidates when none or many."""
    names = list_profiles(pdir)
    hits, bad = [], []
    for n in names:
        try:
            prof = load_profile(pdir / f"{n}.toml", host_checks=False)
        except ProfileError:
            bad.append(n)
            continue
        if mount_for(prof, cwd, ci) is not None:
            hits.append(n)
    if len(hits) == 1:
        return hits[0]
    note = f" (invalid, skipped: {', '.join(bad)})" if bad else ""
    if not hits:
        cands = ", ".join(names) or "none; create one with `agentbox init`"
        raise ResolveError(f"no profile mounts {cwd}; name one explicitly. Profiles: {cands}{note}")
    raise ResolveError(f"several profiles mount {cwd}: {', '.join(hits)}; name one{note}")
