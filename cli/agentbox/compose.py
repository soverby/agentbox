"""Render the per-profile Compose project (PLAN §2, §2.1, §2.2, §2.5).

P3 renders agent, egress, ollama-gate. Router (P5) and mcp-gateway (P6) plug
in through `EXTRA_SERVICES` / egress clients when they exist. The output holds
no secrets: P4 adds Compose `secrets:` with an `environment:` source, so values
stay in the `docker compose up` process env only.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import egress, network
from .profile import Profile, memory_bytes

HOME = "/home/agent"
AGENT_UID = "1000:1000"
EGRESS_UID, GATE_UID = 13, 10001
GATE_PORT = 11434
GATE_LOG_DIR = "/var/log/agentbox"
GATE_LOG = f"{GATE_LOG_DIR}/ollama-gate.log"
DEFAULT_PIDS = 4096
DEFAULT_CPUS = 4  # when [box] resources omits them (same as the init template)
DEFAULT_MEMORY = "8g"
SIDECAR_LIMITS = {"mem_limit": "256m", "pids_limit": 128}
HARDEN = {"cap_drop": ["ALL"], "security_opt": ["no-new-privileges:true"]}
NO_PROXY = "router,mcp-gateway,ollama-gate,localhost,127.0.0.1"
PROXY = f"http://egress:{egress.PORT}"


def project_name(profile: str) -> str:
    return f"agentbox-{profile}"


def home_volume(profile: str) -> str:
    return f"agentbox-{profile}-home"


def agent_env() -> dict[str, str]:
    """Agent env (§2.2, §2.5). The image sets the same values; Compose repeats
    them so they hold even for a derived image that changes ENV."""
    return {
        "HTTPS_PROXY": PROXY,
        "HTTP_PROXY": PROXY,
        "https_proxy": PROXY,
        "http_proxy": PROXY,
        "NO_PROXY": NO_PROXY,
        "no_proxy": NO_PROXY,
        "OLLAMA_HOST": f"http://ollama-gate:{GATE_PORT}",
    }


@dataclass
class Ctx:
    profile: Profile
    n: int  # subnet index
    base: str
    state: Path  # per-profile state dir
    agent_image: str
    egress_image: str
    gate_image: str
    gateway_image: str = ""
    linux: bool = field(default_factory=lambda: sys.platform.startswith("linux"))
    gate_upstream: str = f"http://host.docker.internal:{GATE_PORT}"
    egress_config_hash: str = ""

    @property
    def conf_dir(self) -> Path:
        return self.state / "egress"

    @property
    def egress_logs(self) -> Path:
        return self.state / "logs" / "egress"

    @property
    def gate_logs(self) -> Path:
        return self.state / "logs" / "gate"

    @property
    def compose_file(self) -> Path:
        return self.state / "compose.json"


def _mount_volume(m) -> dict:
    if not m.host_real:
        raise ValueError(f"mount {m.host!r} was not validated on the host (host_checks)")
    return {
        "type": "bind",
        "source": m.host_real,
        "target": m.path,
        "read_only": m.mode == "ro",
        "bind": {"create_host_path": False},
    }


def agent_service(ctx: Ctx) -> dict:
    p = ctx.profile
    ips = network.fixed_ips(ctx.n, ctx.base)
    svc: dict = {
        "image": ctx.agent_image,
        "user": AGENT_UID,
        "init": True,
        "command": ["sleep", "infinity"],
        **HARDEN,
        "pids_limit": DEFAULT_PIDS,
        "networks": {"internal": {"ipv4_address": ips["agent"]}},
        "environment": agent_env(),
        "volumes": [
            {"type": "volume", "source": "home", "target": HOME},
            *(_mount_volume(m) for m in p.mounts),
        ],
        "working_dir": p.mounts[0].path,
        "labels": {"agentbox.profile": p.name},
    }
    r = p.box.resources
    svc["mem_limit"] = memory_bytes(r.memory if r.memory is not None else DEFAULT_MEMORY)
    svc["cpus"] = r.cpus if r.cpus is not None else DEFAULT_CPUS
    return svc


def config_hash(files: dict[str, str]) -> str:
    h = hashlib.sha256()
    for name in sorted(files):
        h.update(name.encode() + b"\0" + files[name].encode() + b"\0")
    return h.hexdigest()[:16]


def egress_service(ctx: Ctx) -> dict:
    ips = network.fixed_ips(ctx.n, ctx.base)
    svc = {
        "image": ctx.egress_image,
        "networks": {"internal": {"ipv4_address": ips["egress"]}, "external": {}},
        "volumes": [
            f"{ctx.conf_dir}:{egress.CONF_DIR}:ro",
            f"{ctx.egress_logs}:{egress.LOG_DIR}",
        ],
        # The squid image declares VOLUME /var/log/squid and /var/spool/squid:
        # tmpfs there, else each create leaks two anonymous volumes.
        "tmpfs": [
            f"/run/squid:uid={EGRESS_UID},gid={EGRESS_UID}",
            "/tmp",
            f"/var/log/squid:uid={EGRESS_UID},gid={EGRESS_UID}",
            f"/var/spool/squid:uid={EGRESS_UID},gid={EGRESS_UID}",
        ],
        **HARDEN,
        "read_only": True,
        **SIDECAR_LIMITS,
        "labels": {"agentbox.egress-config": ctx.egress_config_hash},
    }
    if ctx.linux:  # PLAN §6
        svc["extra_hosts"] = ["host.docker.internal:host-gateway"]
    return svc


def gate_models(profile: Profile) -> str:
    m = profile.models.ollama
    return "local" if m == "local" else json.dumps(list(m))


def gate_service(ctx: Ctx) -> dict:
    ips = network.fixed_ips(ctx.n, ctx.base)
    svc = {
        "image": ctx.gate_image,
        "networks": {"internal": {"ipv4_address": ips["ollama-gate"]}, "external": {}},
        "environment": {
            "GATE_UPSTREAM": ctx.gate_upstream,
            "GATE_MODELS": gate_models(ctx.profile),
            "GATE_LOG": GATE_LOG,
        },
        "volumes": [f"{ctx.gate_logs}:{GATE_LOG_DIR}"],
        **HARDEN,
        "read_only": True,
        **SIDECAR_LIMITS,
    }
    if ctx.linux:
        svc["extra_hosts"] = ["host.docker.internal:host-gateway"]
    return svc


def _gateway_service(ctx: Ctx) -> dict:
    from . import mcpgw

    return mcpgw.service(ctx)


# Extension point (name -> fn(ctx)). P6: the MCP gateway always runs (§2.6).
# P5 adds "router".
EXTRA_SERVICES: dict = {"mcp-gateway": _gateway_service}


def escape_dollars(v):
    """Compose interpolates `$VAR` / `${VAR}` in every string, and the
    `compose up` env holds AGENTBOX_SECRET_* values: escape `$` as `$$` in
    every string value (recursively) so nothing from a profile can pull a
    secret into container config (PLAN §2.4)."""
    if isinstance(v, str):
        return v.replace("$", "$$")
    if isinstance(v, dict):
        return {k: escape_dollars(x) for k, x in v.items()}
    if isinstance(v, list):
        return [escape_dollars(x) for x in v]
    return v


def render(ctx: Ctx) -> dict:
    return escape_dollars(_render(ctx))


def _render(ctx: Ctx) -> dict:
    p = ctx.profile
    services = {
        "agent": agent_service(ctx),
        "egress": egress_service(ctx),
        "ollama-gate": gate_service(ctx),
    }
    for name, fn in EXTRA_SERVICES.items():
        services[name] = fn(ctx)
    return {
        "name": project_name(p.name),
        "services": services,
        "networks": {
            "internal": {
                "internal": True,
                "ipam": {"config": [{"subnet": str(network.subnet_for(ctx.n, ctx.base))}]},
            },
            "external": {},
        },
        "volumes": {"home": {"name": home_volume(p.name)}},
    }


def egress_clients(ctx: Ctx, agent_domains: list[str]) -> list[egress.Client]:
    """Egress ACL clients: the agent, plus each sidecar that runs (P5/P6)."""
    ips = network.fixed_ips(ctx.n, ctx.base)
    clients = [egress.Client("agent", ips["agent"], agent_domains)]
    if "router" in EXTRA_SERVICES:
        raise NotImplementedError("router egress allowlist is P5")
    if "mcp-gateway" in EXTRA_SERVICES:
        from . import mcpgw

        clients.append(
            egress.Client("mcp-gateway", ips["mcp-gateway"], mcpgw.egress_domains(ctx.profile))
        )
    return clients


def write_json(path: Path, doc: dict) -> None:
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(doc, indent=1) + "\n")
    os.chmod(tmp, 0o600)
    tmp.replace(path)
