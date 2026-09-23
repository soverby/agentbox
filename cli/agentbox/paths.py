"""Host paths (PLAN §2.3). Every root is overridable by env so tests never
touch the real config or state dirs.

- AGENTBOX_CONFIG_HOME  [~/.config/agentbox]       config.toml, profiles/
- AGENTBOX_STATE_HOME   [~/.local/state/agentbox]  <profile>/ (0700)
- AGENTBOX_REPO         [repo of this editable package] images/, presets/, tests/isolation/
"""

from __future__ import annotations

import os
import re
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


BACKENDS = ("keychain", "op", "env")
PREFIX_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
OP_VAULT_RE = re.compile(r"[^/\s\"\\]+")
CONFIG_KEYS = ("subnet_base", "secret_backend", "secret_prefix", "op_vault", "runs_keep")


@dataclass(frozen=True)
class Config:
    subnet_base: str = DEFAULT_BASE
    # Backend for default secret locations (PLAN §2.4, §7: keychain). Refs with
    # an explicit scheme in a profile always use that scheme's backend.
    secret_backend: str = "keychain"
    # First part of the default service name: <prefix>/<profile|_shared>/<NAME>.
    # Tests set it to agentbox-test-<rand> so they never touch real items.
    secret_prefix: str = "agentbox"
    op_vault: str | None = None  # needed when secret_backend = "op"
    runs_keep: int = 200  # headless run dirs kept per profile (oldest pruned)


def config_file() -> Path:
    return config_home() / "config.toml"


def load_config() -> Config:
    """~/.config/agentbox/config.toml. Missing file: defaults. Unknown key: error."""
    f = config_file()
    if not f.is_file():
        return Config()
    try:
        data = tomllib.loads(f.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as e:
        raise ConfigError(f"{f}: {e}") from None
    unknown = set(data) - set(CONFIG_KEYS)
    if unknown:
        raise ConfigError(f"{f}: unknown key(s) {', '.join(sorted(unknown))}")
    for k in CONFIG_KEYS:
        if k in data and not isinstance(data[k], str):
            raise ConfigError(f"{f}: {k} must be a string")
    base = data.get("subnet_base", DEFAULT_BASE)
    try:
        parse_base(base)
    except NetworkError as e:
        raise ConfigError(f"{f}: {e}") from None
    backend = data.get("secret_backend", "keychain")
    if backend not in BACKENDS:
        raise ConfigError(f"{f}: secret_backend must be one of {', '.join(BACKENDS)}")
    prefix = data.get("secret_prefix", "agentbox")
    if not PREFIX_RE.fullmatch(prefix):
        raise ConfigError(f"{f}: secret_prefix must match {PREFIX_RE.pattern}")
    vault = data.get("op_vault")
    if vault is not None and not OP_VAULT_RE.fullmatch(vault):
        raise ConfigError(f"{f}: op_vault is not a valid 1Password vault name")
    if backend == "op" and vault is None:
        raise ConfigError(f'{f}: secret_backend = "op" needs op_vault')
    keep = data.get("runs_keep", "200")
    if not keep.isdigit() or int(keep) < 1:
        raise ConfigError(f'{f}: runs_keep must be a whole number >= 1, as a string ("200")')
    return Config(subnet_base=base, secret_backend=backend, secret_prefix=prefix, op_vault=vault,
                  runs_keep=int(keep))  # fmt: skip


def write_config(values: dict[str, str]) -> Path:
    """Write config.toml (flat string keys, 0600) after validating it."""
    f = config_file()
    f.parent.mkdir(parents=True, exist_ok=True)
    lines = [f"{k} = {_toml_str(values[k])}" for k in CONFIG_KEYS if k in values]
    tmp = f.with_name(f".{f.name}.tmp")
    tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(f)
    load_config()
    return f


def read_config_values() -> dict[str, str]:
    f = config_file()
    if not f.is_file():
        return {}
    load_config()  # validates
    return dict(tomllib.loads(f.read_text(encoding="utf-8")))


def _toml_str(v: str) -> str:
    if any(ord(c) < 0x20 or c in '"\\' or ord(c) == 0x7F for c in v):
        raise ConfigError(f"config value {v!r} has characters this writer does not quote")
    return f'"{v}"'
