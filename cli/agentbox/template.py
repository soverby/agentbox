"""Default profile that `agentbox init` writes (PLAN §2.3)."""

from __future__ import annotations

import json

from .profile import AGENTS

_TEMPLATE = """\
[box]
agents = {agents}
resources = {{ cpus = 4, memory = "8g" }}
# packages = ["ffmpeg"]
# web_tools = true

[[mount]]
host = {mount}
mode = "rw"                  # init writes rw for the project; schema default is ro
# path defaults to the same absolute path as on the host

[network]
mode = {mode}              # or "{other}"
presets = ["anthropic", "openai", "github", "dev"]
allow = []

[secrets]
# NAME = "shared": agent, keychain agentbox/_shared/NAME.
# NAME = {{ to = "...", ref = "..." }}: defaults agent + agentbox/<profile>/NAME.
GH_TOKEN = "shared"
# CLAUDE_CODE_OAUTH_TOKEN is implicit (shared) when "claude" is in agents.

[models]
ollama = "local"             # all non-cloud models on the host; or a list

# [models.remote.qwen-modal]
# api_base = "https://<workspace>--vllm-serve.modal.run/v1"
# key = "MODAL_API_KEY"      # goes to router automatically

# [mcp.servers.docs]
# url = "https://mcp.example.com/mcp"
# bearer = "DOCS_MCP_TOKEN"  # goes to mcp-gateway automatically; or auth = "oauth"
# tools = ["search", "fetch"]
"""


def _toml_str(s: str) -> str:
    # JSON string escaping is valid TOML basic-string escaping.
    return json.dumps(s, ensure_ascii=False)


def render_default_profile(
    name: str, mount: str, agents: list[str] | None = None, open_mode: bool = False
) -> str:
    """Return the profile TOML for `agentbox init`.

    `name` is not written into the file (the file name carries it); it is
    accepted so the caller can validate the result as that profile.
    """
    del name
    agents = list(AGENTS) if agents is None else agents
    return _TEMPLATE.format(
        agents="[" + ", ".join(_toml_str(a) for a in agents) + "]",
        mount=_toml_str(mount),
        mode='"open"  ' if open_mode else '"strict"',
        other="strict" if open_mode else "open",
    )
