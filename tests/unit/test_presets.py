from pathlib import Path

import pytest
from agentbox import presets
from agentbox.profile import hostname_problem


def test_shipped_presets_valid():
    for name in ("anthropic", "openai", "github", "dev"):
        doms = presets.load_preset(name)
        assert doms
        assert all(hostname_problem(d) is None for d in doms)
        assert "mcp-proxy.anthropic.com" not in doms


def test_anthropic_preset_has_plan_minimum():
    doms = presets.load_preset("anthropic")
    for d in ("api.anthropic.com", "claude.ai", "claude.com", "platform.claude.com"):
        assert d in doms


def test_unknown_preset_is_error():
    with pytest.raises(presets.PresetError, match="unknown preset"):
        presets.load_preset("nope")


def test_bad_preset_name():
    with pytest.raises(presets.PresetError):
        presets.load_preset("../etc")


def test_merge_presets_and_allow(tmp_path: Path):
    (tmp_path / "a.toml").write_text('domains = ["x.com", "y.com"]\n')
    (tmp_path / "b.toml").write_text('domains = [".y.com", "z.com"]\n')
    out = presets.agent_allowlist(["a", "b"], ["Z.com", "new.org"], tmp_path)
    assert out == ["x.com", ".y.com", "z.com", "new.org"]


def test_preset_extra_key_rejected(tmp_path: Path):
    (tmp_path / "a.toml").write_text('domains = ["x.com"]\nother = 1\n')
    with pytest.raises(presets.PresetError):
        presets.load_preset("a", tmp_path)


def test_preset_invalid_domain_rejected(tmp_path: Path):
    (tmp_path / "a.toml").write_text('domains = ["1.2.3.4"]\n')
    with pytest.raises(presets.PresetError):
        presets.load_preset("a", tmp_path)


@pytest.mark.parametrize(
    "d", ["mcp-proxy.anthropic.com", ".anthropic.com", ".MCP-proxy.anthropic.com"]
)
def test_mcp_proxy_never_allowed(tmp_path: Path, d):
    with pytest.raises(presets.PresetError, match="never allowed"):
        presets.agent_allowlist([], [d], tmp_path)


def test_other_anthropic_subdomain_ok(tmp_path: Path):
    assert presets.agent_allowlist([], ["api.anthropic.com"], tmp_path) == ["api.anthropic.com"]
