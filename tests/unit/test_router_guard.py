"""Router pre-call guard rules (images/router/agentbox_guard.py; PLAN §2.5)."""

import importlib.util
import sys
from pathlib import Path

import pytest

_f = Path(__file__).resolve().parents[2] / "images" / "router" / "agentbox_guard.py"
_spec = importlib.util.spec_from_file_location("agentbox_guard_t", _f)
g = importlib.util.module_from_spec(_spec)
sys.modules["agentbox_guard_t"] = g
_spec.loader.exec_module(g)

MSG = [{"role": "user", "content": "x"}]
INTERNAL = {"litellm_call_id": "i", "litellm_logging_obj": object(), "proxy_server_request": {},
            "secret_fields": {}}  # fmt: skip


@pytest.mark.parametrize("key", ["extra_headers", "headers", "api_key", "extra_body", "API_KEY",
                                 "Extra_Headers", "api_base", "base_url", "custom_api_base",
                                 "openai_base_url", "x_headers", "user_config"])  # fmt: skip
@pytest.mark.parametrize("call_type", ["acompletion", "anthropic_messages", "aresponses"])
def test_banned_top_level(key, call_type):
    with pytest.raises(g.Refused, match=key):
        g.check({"model": "m", "messages": MSG, key: {"Host": "evil"}, **INTERNAL}, call_type)


def test_banned_nested_metadata():
    for ct, d in (
        ("anthropic_messages", {"metadata": {"my_API_BASE": "x"}}),
        ("aresponses", {"litellm_metadata": {"requester_metadata": {"x_headers": 1}}}),
        ("acompletion", {"metadata": {"extra_headers": {}, "headers": {"host": "router"}}}),
    ):
        with pytest.raises(g.Refused):
            g.check({"model": "m", **d}, ct)
    # LiteLLM's own request-header log in chat metadata is not a client field
    d = {"model": "m", "metadata": {"headers": {"host": "router:4000"}, "user_id": "u"}}
    assert g.check(d, "acompletion") == []


def test_mcp_tool_refused():
    with pytest.raises(g.Refused, match="mcp"):
        g.check({"model": "m", "input": "x", "tools": [{"type": "mcp", "server_url": "x"}]},
                "aresponses")  # fmt: skip


@pytest.mark.parametrize("kind", ["MCP", "Mcp", "mCp"])
def test_mcp_tool_refused_any_case(kind):
    with pytest.raises(g.Refused, match="mcp"):
        g.check({"model": "m", "input": "x", "tools": [{"type": kind, "server_url": "x"}]},
                "aresponses")  # fmt: skip


def test_unknown_dropped_known_kept():
    d = {"model": "m", "messages": MSG, "stream": True, "tools": [], "system": "s",
         "input": "i", "reasoning": {}, "foo": 1, "mock_response": "x", "litellm_foo": 1,
         **INTERNAL}  # fmt: skip
    dropped = g.check(d, "acompletion")
    assert sorted(dropped) == ["foo", "litellm_foo", "mock_response"]
    assert set(d) == {"model", "messages", "stream", "tools", "system", "input", "reasoning",
                      *INTERNAL}  # fmt: skip
