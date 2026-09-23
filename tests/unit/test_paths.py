"""Config/state paths and env overrides."""

import pytest
from agentbox import paths


def test_env_overrides(tmp_path, monkeypatch):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path / "c"))
    monkeypatch.setenv("AGENTBOX_STATE_HOME", str(tmp_path / "s"))
    assert paths.profile_file("p") == tmp_path / "c" / "profiles" / "p.toml"
    d = paths.state_dir("p")
    assert d == tmp_path / "s" / "p"
    assert d.stat().st_mode & 0o777 == 0o700
    assert (tmp_path / "s").stat().st_mode & 0o777 == 0o700
    for sub in ("logs/egress", "logs/gate", "runs"):
        assert (d / sub).is_dir()


def test_defaults(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTBOX_CONFIG_HOME", raising=False)
    monkeypatch.delenv("AGENTBOX_STATE_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    assert paths.config_home() == tmp_path / ".config" / "agentbox"
    assert paths.state_home() == tmp_path / ".local" / "state" / "agentbox"


def test_repo_root(monkeypatch, tmp_path):
    monkeypatch.delenv("AGENTBOX_REPO", raising=False)
    assert (paths.repo_root() / "images/agent/build.sh").is_file()
    monkeypatch.setenv("AGENTBOX_REPO", str(tmp_path))
    with pytest.raises(paths.ConfigError):
        paths.repo_root()


def test_config(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    assert paths.load_config().subnet_base == "10.213.0.0/16"
    (tmp_path / "config.toml").write_text('subnet_base = "10.99.0.0/16"\n')
    assert paths.load_config().subnet_base == "10.99.0.0/16"
    (tmp_path / "config.toml").write_text('subnet_base = "8.8.0.0/16"\n')
    with pytest.raises(paths.ConfigError, match="private"):
        paths.load_config()
    (tmp_path / "config.toml").write_text("bogus = 1\n")
    with pytest.raises(paths.ConfigError, match="unknown"):
        paths.load_config()
