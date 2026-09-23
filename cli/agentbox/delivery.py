"""Secret delivery into the box (PLAN §2.4).

- Compose `secrets:` with an `environment:` source. The rendered file holds
  only names and env var names; the values go only into the environment of
  the `docker compose up` process (`compose_env`).
- Each service gets `/run/secrets/<NAME>` for the secrets that target it.
- Label `agentbox.secrets` on each target service = HMAC-SHA256 over its
  (name, value) set, keyed by a per-profile random key (state, 0600). Compose
  does not see secret content, so the label makes a changed set recreate
  exactly the affected container. A plain hash of a value is never stored.
- Per-box random tokens (MCP_GATEWAY_TOKEN, AGENTBOX_ROUTER_MASTER_KEY) live
  in state (0600), are made at the first `up`, and are replaced at `down`.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets as pysecrets
from dataclasses import dataclass, field
from pathlib import Path

from . import secretstore
from .paths import Config
from .profile import CLAUDE_TOKEN, Profile

MCP_GATEWAY_TOKEN = "MCP_GATEWAY_TOKEN"
ROUTER_MASTER_KEY = "AGENTBOX_ROUTER_MASTER_KEY"  # reserved name (AGENTBOX_*)
# name -> targets. Only services that are rendered receive them.
BOX_TOKENS = {MCP_GATEWAY_TOKEN: ["agent", "mcp-gateway"], ROUTER_MASTER_KEY: ["agent", "router"]}
# A box token goes to the agent only when this sidecar runs (no router key in
# a box without a router).
TOKEN_NEEDS = {ROUTER_MASTER_KEY: "router"}
# LiteLLM refuses a master key that does not start with "sk-".
TOKEN_PREFIX = {ROUTER_MASTER_KEY: "sk-"}
TARGET_SERVICES = ("agent", "router", "mcp-gateway")
LABEL = "agentbox.secrets"
TOKENS_FILE = "box-tokens.json"
KEY_FILE = "secrets-hmac.key"
ENV_PREFIX = "AGENTBOX_SECRET_"
# /run/secrets file mode per service. No uid/gid: when either is set, Compose
# asks the daemon for CopyUIDGID, which chowns the file to the container user
# (verified: uid "0" and "65534" both became 1000), and the agent could then
# chmod and rewrite it. Without them the tar header's root:root is kept.
# Agent: root:root 0444: readable, not writable, not chmod-able, not removable
# (/run/secrets is root 0755). PLAN §2.4 says root:agent 0440; Compose cannot
# set a group without the chown, see the P4 round-2 report.
# mcp-gateway: root:root 0444 for the same reason (no uid/gid, so no chown);
# "other" read is what lets the non-root gateway user (uid 10002) read them.
# Every process in the gateway container runs as that uid, so stdio MCP
# servers it spawns could read these files too (they get no secret env).
# router: root:root 0444 too; the router runs as uid 10003.
SECRET_MODE = {"agent": "0444", "mcp-gateway": "0444", "router": "0444"}


@dataclass
class Missing:
    name: str
    ref: str
    targets: list[str]


@dataclass
class Delivery:
    values: dict[str, str] = field(default_factory=dict)  # present, needed secrets
    targets: dict[str, list[str]] = field(default_factory=dict)  # every declared name
    missing: list[Missing] = field(default_factory=list)

    def names_for(self, target: str) -> list[str]:
        return sorted(n for n, t in self.targets.items() if target in t and n in self.values)


def _write_private(path: Path, data: bytes) -> None:
    tmp = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    tmp.replace(path)


def hmac_key(state: Path) -> bytes:
    f = state / KEY_FILE
    if f.is_file():
        key = f.read_bytes()
        if len(key) == 32:
            return key
    key = pysecrets.token_bytes(32)
    _write_private(f, key)
    return key


def _new_tokens() -> dict[str, str]:
    return {n: TOKEN_PREFIX.get(n, "") + pysecrets.token_urlsafe(32) for n in BOX_TOKENS}


def box_tokens(state: Path) -> dict[str, str]:
    """Per-box tokens; made on first use."""
    f = state / TOKENS_FILE
    if f.is_file():
        try:
            data = json.loads(f.read_text())
        except ValueError:
            data = {}
        if isinstance(data, dict) and set(data) == set(BOX_TOKENS):
            return data
    data = _new_tokens()
    _write_private(f, json.dumps(data).encode())
    return data


def rotate_box_tokens(state: Path) -> None:
    """New tokens for the next `up` (called at `down`)."""
    if state.is_dir():
        _write_private(state / TOKENS_FILE, json.dumps(_new_tokens()).encode())


def collect(
    profile: Profile,
    cfg: Config,
    state: Path | None,
    services: set[str] | None = None,
    fetch=None,
) -> Delivery:
    """Read the secrets that the given services need (default: all targets)
    from the backends. A secret none of those services use is not read."""
    services = set(TARGET_SERVICES) if services is None else services
    fetch = fetch or secretstore.fetcher(cfg, profile.name)
    d = Delivery()
    for s in profile.secrets.values():
        d.targets[s.name] = list(s.to)
        if not services & set(s.to):
            continue
        ref = secretstore.ref_for(s, profile.name, cfg)
        v = fetch(ref)
        if v is None:
            d.missing.append(Missing(s.name, ref, list(s.to)))
            continue
        if msg := secretstore.value_problem(v):
            raise secretstore.SecretError(f"{s.name} ({ref}): {msg}")
        d.values[s.name] = v
    if state is not None:
        for n, v in box_tokens(state).items():
            need = TOKEN_NEEDS.get(n)
            if need is not None and (need not in services or not profile.models.remote):
                continue
            d.targets[n] = list(BOX_TOKENS[n])
            if services & set(BOX_TOKENS[n]):
                d.values[n] = v
    return d


def env_var(name: str) -> str:
    return ENV_PREFIX + name


def label(key: bytes, items: dict[str, str]) -> str:
    """HMAC-SHA256 over the sorted (name, value) pairs, length-prefixed."""
    h = hmac.new(key, digestmod=hashlib.sha256)
    for n in sorted(items):
        for part in (n.encode(), items[n].encode()):
            h.update(len(part).to_bytes(4, "big") + part)
    return h.hexdigest()


def apply(doc: dict, d: Delivery, key: bytes) -> None:
    """Add `secrets:` to the rendered Compose document (names only)."""
    used: set[str] = set()
    for svc_name, svc in doc["services"].items():
        if svc_name not in TARGET_SERVICES:
            continue
        names = d.names_for(svc_name)
        entries = []
        for n in names:
            e = {"source": n, "target": n}
            if svc_name in SECRET_MODE:
                e["mode"] = SECRET_MODE[svc_name]
            entries.append(e)
        if entries:
            svc["secrets"] = entries
        svc.setdefault("labels", {})[LABEL] = label(key, {n: d.values[n] for n in names})
        used.update(names)
    if used:
        doc["secrets"] = {n: {"environment": env_var(n)} for n in sorted(used)}


def compose_env(d: Delivery, doc: dict) -> dict[str, str]:
    """Env for the `docker compose up` process: exactly the used secrets."""
    return {env_var(n): d.values[n] for n in doc.get("secrets", {}) if n in d.values}


def claude_hint(d: Delivery, profile: Profile) -> str | None:
    if "claude" in profile.box.agents and any(m.name == CLAUDE_TOKEN for m in d.missing):
        return (
            f"{CLAUDE_TOKEN} is not set: Claude sessions will ask for a login. "
            "Run `agentbox setup` to store the shared token."
        )
    return None
