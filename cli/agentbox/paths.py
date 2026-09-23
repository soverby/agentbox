"""Host paths (PLAN §2.3). Every root is overridable by env so tests never
touch the real config or state dirs.

- AGENTBOX_CONFIG_HOME  [~/.config/agentbox]       config.toml, profiles/
- AGENTBOX_STATE_HOME   [~/.local/state/agentbox]  <profile>/ (0700)
- AGENTBOX_REPO         [repo of this editable package] images/, presets/, tests/isolation/
"""

from __future__ import annotations

import os
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .network import DEFAULT_BASE, NetworkError, parse_base


class ConfigError(Exception):
    pass


def config_home() -> Path:
    v = os.environ.get("AGENTBOX_CONFIG_HOME")
    return Path(v) if v else Path.home() / ".config" / "agentbox"


def state_home() -> Path:
    v = os.environ.get("AGENTBOX_STATE_HOME")
    return Path(v) if v else Path.home() / ".local" / "state" / "agentbox"


def repo_root() -> Path:
    v = os.environ.get("AGENTBOX_REPO")
    root = Path(v) if v else Path(__file__).resolve().parents[2]
    if not (root / "images" / "agent" / "build.sh").is_file():
        raise ConfigError(
            f"{root} is not an agentbox repo (no images/agent/build.sh); "
            "install with `uv tool install -e ./cli` or set AGENTBOX_REPO"
        )
    return root


def profiles_dir() -> Path:
    return config_home() / "profiles"


def profile_file(name: str) -> Path:
    return profiles_dir() / f"{name}.toml"


def state_dir(name: str, create: bool = True) -> Path:
    """Per-profile state dir (0700) with logs/egress, logs/gate, runs/."""
    root = state_home()
    d = root / name
    if create:
        for p in (root, d, d / "logs", d / "logs" / "egress", d / "logs" / "gate", d / "runs"):
            p.mkdir(parents=True, exist_ok=True)
        os.chmod(root, 0o700)
        os.chmod(d, 0o700)
    return d


@dataclass(frozen=True)
class Config:
    subnet_base: str = DEFAULT_BASE


def load_config() -> Config:
    """~/.config/agentbox/config.toml. Missing file: defaults. Unknown key: error."""
    f = config_home() / "config.toml"
    if not f.is_file():
        return Config()
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"{f}: {e}") from None
    unknown = set(data) - {"subnet_base"}
    if unknown:
        raise ConfigError(f"{f}: unknown key(s) {', '.join(sorted(unknown))}")
    base = data.get("subnet_base", DEFAULT_BASE)
    if not isinstance(base, str):
        raise ConfigError(f"{f}: subnet_base must be a string")
    try:
        parse_base(base)
    except NetworkError as e:
        raise ConfigError(f"{f}: {e}") from None
    return Config(subnet_base=base)
