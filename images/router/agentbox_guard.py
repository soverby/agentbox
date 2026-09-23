"""agentbox router guard: LiteLLM pre-call hook (PLAN §2.5).

Loaded by `litellm_settings.callbacks: ["agentbox_guard.guard"]`; baked into
the router image, root-owned 0644 (`/opt/agentbox-router`, on PYTHONPATH), so
neither the box nor the host state dir can change it.

LiteLLM 1.102.1 accepts request-body fields that change the upstream call:
`extra_headers` / `headers` (sent upstream next to the remote key, even
`Host`), `api_key` (replaces the remote key), `extra_body`, `api_base`-like
fields. The hook runs in `ProxyBaseLLMRequestProcessing` (common_request_
processing.py `proxy_logging_obj.pre_call_hook`) for /v1/chat/completions,
/chat/completions (call_type acompletion), /v1/messages (anthropic_messages)
and /v1/responses (aresponses) — verified against the pinned image.

Rules:
1. 400 when a top-level key, or a key one level down in the client's
   metadata, is in BANNED or matches *api_base* / *base_url* / *_headers
   (case-insensitive); 400 for a tool of type "mcp" (server-side MCP calls
   from the router).
2. Top-level keys outside the union of the OpenAI chat-completions,
   Anthropic messages, and OpenAI Responses request parameters (and
   LiteLLM's own internal keys) are dropped; their names are logged.
Values are never logged.
"""

from __future__ import annotations

import sys

try:
    from fastapi import HTTPException
    from litellm.integrations.custom_logger import CustomLogger
except ImportError:  # host unit tests import the pure rules only
    HTTPException = None
    CustomLogger = object


class Refused(ValueError):
    pass


BANNED = frozenset(
    {"extra_headers", "headers", "api_key", "extra_body", "user_config", "api_version",
     "litellm_params", "model_list", "fallbacks", "context_window_fallbacks"}
)  # fmt: skip
BANNED_PARTS = ("api_base", "base_url")
BANNED_SUFFIX = "_headers"

# https://platform.openai.com/docs/api-reference/chat/create
OPENAI_CHAT = frozenset(
    {"messages", "model", "audio", "frequency_penalty", "function_call", "functions",
     "logit_bias", "logprobs", "max_completion_tokens", "max_tokens", "metadata",
     "modalities", "n", "parallel_tool_calls", "prediction", "presence_penalty",
     "prompt_cache_key", "prompt_cache_retention", "reasoning_effort", "response_format",
     "safety_identifier", "seed", "service_tier", "stop", "store", "stream",
     "stream_options", "temperature", "tool_choice", "tools", "top_logprobs", "top_p",
     "user", "verbosity", "web_search_options"}
)  # fmt: skip
# https://docs.anthropic.com/en/api/messages (no `mcp_servers`, `container`:
# server-side connectors / code execution the router must not run)
ANTHROPIC_MESSAGES = frozenset(
    {"model", "messages", "max_tokens", "metadata", "service_tier", "stop_sequences",
     "stream", "system", "temperature", "thinking", "tool_choice", "tools", "top_k",
     "top_p", "context_management", "output_config", "output_format"}
)  # fmt: skip
# https://platform.openai.com/docs/api-reference/responses/create
OPENAI_RESPONSES = frozenset(
    {"background", "conversation", "include", "input", "instructions",
     "max_output_tokens", "max_tool_calls", "metadata", "model", "parallel_tool_calls",
     "previous_response_id", "prompt", "prompt_cache_key", "prompt_cache_retention",
     "reasoning", "safety_identifier", "service_tier", "store", "stream",
     "stream_options", "temperature", "text", "tool_choice", "tools", "top_logprobs",
     "top_p", "truncation", "user", "client_metadata"}
)  # fmt: skip
ALLOWED = OPENAI_CHAT | ANTHROPIC_MESSAGES | OPENAI_RESPONSES
# Keys LiteLLM itself puts into `data` before the hook (captured on 1.102.1).
INTERNAL = frozenset(
    {"litellm_call_id", "litellm_logging_obj", "litellm_metadata", "proxy_server_request",
     "secret_fields", "metadata"}
)  # fmt: skip
# On /chat/completions LiteLLM merges the client's metadata into its own
# data["metadata"], where it also stores the request headers under "headers"
# (for logging; never sent upstream). That one name is skipped there.
LITELLM_METADATA_HEADERS = "headers"


def banned(key) -> bool:
    if not isinstance(key, str):
        return True
    k = key.lower()
    return k in BANNED or any(p in k for p in BANNED_PARTS) or k.endswith(BANNED_SUFFIX)


def client_metadata(data: dict, call_type: str) -> list[dict]:
    """The client's metadata dicts (one level down is checked)."""
    out = []
    for holder in ("metadata", "litellm_metadata"):
        md = data.get(holder)
        if not isinstance(md, dict):
            continue
        rm = md.get("requester_metadata")
        if isinstance(rm, dict):
            out.append({k: v for k, v in rm.items() if k != "headers"})
        if holder == "metadata":
            if call_type == "acompletion":
                out.append({k: v for k, v in md.items() if k != LITELLM_METADATA_HEADERS})
            else:
                out.append(md)  # /v1/messages, /v1/responses: the client's own
    return out


def check(data: dict, call_type: str) -> list[str]:
    """Raise 400 on a banned field; drop unknown top-level keys. Returns the
    names of dropped keys."""
    bad = [k for k in data if banned(k)]
    for md in client_metadata(data, call_type):
        bad += [f"metadata.{k}" for k in md if banned(k)]
    tools = data.get("tools")
    if isinstance(tools, list) and any(
        isinstance(t, dict) and str(t.get("type", "")).lower() == "mcp" for t in tools
    ):
        bad.append("tools[type=mcp]")
    if bad:
        raise Refused("agentbox router: request field not allowed: "
                      + ", ".join(sorted({str(b)[:64] for b in bad})))  # fmt: skip
    dropped = []
    for k in list(data):
        if k in ALLOWED or k in INTERNAL:
            continue
        dropped.append(k)
        del data[k]
    return dropped


class Guard(CustomLogger):
    async def async_pre_call_hook(self, user_api_key_dict, cache, data, call_type):
        try:
            dropped = check(data, str(call_type))
        except Refused as e:
            raise HTTPException(status_code=400, detail={"error": str(e)}) from None
        if dropped:
            names = ", ".join(sorted(str(k)[:64] for k in dropped))
            print(f"agentbox-guard: {call_type}: dropped fields: {names}", file=sys.stderr,
                  flush=True)  # fmt: skip
        return data


guard = Guard()
