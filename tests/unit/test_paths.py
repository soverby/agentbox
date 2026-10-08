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


# ---------------------------------------------------------------- report keys (PLAN §2.8)
def cfg_with(tmp_path, monkeypatch, text):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    (tmp_path / "config.toml").write_text(text)
    return paths.load_config()


def test_report_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    c = paths.load_config()
    assert (c.report_outputs, c.report_command, c.report_investigator) == (("slack",), None, None)
    assert paths.REPORT_OUTPUTS == ("stdout", "json", "slack", "command")
    for k in ("report_outputs", "report_command", "report_investigator"):
        assert k in paths.CONFIG_KEYS


def test_report_keys_valid(monkeypatch, tmp_path):
    c = cfg_with(tmp_path, monkeypatch, 'report_outputs = "stdout, json,slack"\n')
    assert c.report_outputs == ("stdout", "json", "slack")
    c = cfg_with(tmp_path, monkeypatch, 'report_outputs = "slack,command"\n'
                 'report_command = "/usr/local/bin/hook --flag \\"two words\\""\n'
                 'report_investigator = "investigator"\n')  # fmt: skip
    assert c.report_command == ("/usr/local/bin/hook", "--flag", "two words")
    assert c.report_investigator == "investigator"
    # a command may be set without being used
    assert cfg_with(tmp_path, monkeypatch, 'report_command = "/bin/true"\n').report_command == (
        "/bin/true",)  # fmt: skip


@pytest.mark.parametrize(
    "text,msg",
    [
        ('report_outputs = "sms"\n', "unknown output 'sms'"),
        ('report_outputs = "slack,slack"\n', "listed twice"),
        ('report_outputs = ""\n', "unknown output"),
        ('report_outputs = "slack,"\n', "unknown output"),
        ("report_outputs = 1\n", "must be a string"),
        ('report_outputs = "command"\n', "needs report_command"),
        ('report_command = "hook.sh"\n', "absolute path"),
        ('report_command = "./hook.sh"\n', "absolute path"),
        ('report_command = ""\n', "empty"),
        ('report_command = "/bin/x \\"unclosed"\n', "report_command"),
        ("report_command = 5\n", "must be a string"),
        ('report_investigator = "Bad_Name"\n', "profile name"),
        ('report_investigator = "_x"\n', "profile name"),
        ("report_investigator = true\n", "must be a string"),
        ('report_output = "slack"\n', "unknown key"),
    ],
)
def test_report_keys_invalid(monkeypatch, tmp_path, text, msg):
    with pytest.raises(paths.ConfigError, match=msg):
        cfg_with(tmp_path, monkeypatch, text)


def test_write_config_round_trips_the_report_keys(monkeypatch, tmp_path):
    monkeypatch.setenv("AGENTBOX_CONFIG_HOME", str(tmp_path))
    vals = {"secret_backend": "keychain", "report_outputs": "stdout,slack",
            "report_command": "/usr/bin/true", "report_investigator": "inv"}  # fmt: skip
    f = paths.write_config(vals)
    assert f.stat().st_mode & 0o777 == 0o600
    assert paths.read_config_values() == vals
    c = paths.load_config()
    assert c.report_outputs == ("stdout", "slack") and c.report_investigator == "inv"
    with pytest.raises(paths.ConfigError):  # validated before it is kept
        paths.write_config({"report_outputs": "nope"})
