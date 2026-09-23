"""Network allowlist presets (PLAN §2.2)."""

from __future__ import annotations

import tomllib
from pathlib import Path

from .profile import ITEM_NAME_RE, hostname_problem, merge_domains

DEFAULT_PRESET_DIR = Path(__file__).resolve().parents[2] / "presets"


# Claude.ai connector proxy: never reachable from a box (PLAN §2.6, T5).
FORBIDDEN = ("mcp-proxy.anthropic.com",)


class PresetError(Exception):
    pass


def forbidden_problem(entry: str) -> str | None:
    """An allowlist entry that equals or covers a forbidden host."""
    e = entry.lower()
    for f in FORBIDDEN:
        if e.lstrip(".") == f or (e.startswith(".") and ("." + f).endswith(e)):
            return f"{entry!r} would allow {f}, which is never allowed"
    return None


def load_preset(name: str, preset_dir: Path = DEFAULT_PRESET_DIR) -> list[str]:
    """Return the domain list of one preset. Unknown or invalid preset: error."""
    if ITEM_NAME_RE.fullmatch(name) is None:
        raise PresetError(f"invalid preset name {name!r}")
    path = Path(preset_dir) / f"{name}.toml"
    if not path.is_file():
        raise PresetError(f"unknown preset {name!r} (no {path})")
    with path.open("rb") as f:
        data = tomllib.load(f)
    if set(data) != {"domains"}:
        raise PresetError(f"preset {name}: only key 'domains' is allowed")
    domains = data["domains"]
    if not isinstance(domains, list) or not all(isinstance(d, str) for d in domains):
        raise PresetError(f"preset {name}: 'domains' must be a list of strings")
    for d in domains:
        if msg := hostname_problem(d) or forbidden_problem(d):
            raise PresetError(f"preset {name}: {d!r}: {msg}")
    return domains


def agent_allowlist(
    presets: list[str], allow: list[str], preset_dir: Path = DEFAULT_PRESET_DIR
) -> list[str]:
    """Strict-mode agent allowlist: presets in order, then profile `allow`."""
    lists = [load_preset(p, preset_dir) for p in presets]
    for d in allow:
        if msg := hostname_problem(d) or forbidden_problem(d):
            raise PresetError(f"allow: {d!r}: {msg}")
    return merge_domains(*lists, allow)
