"""Model router (PLAN §2.5): LiteLLM for `[models.remote.*]`, only when the
profile has remote models.

- Config (`<state>/router/config.yaml`, bind-mounted ro): rendered by the CLI
  as JSON (YAML is a superset; LiteLLM reads it with `yaml.safe_load`). It
  holds names only: every key is `os.environ/<NAME>`, and the router's
  entrypoint shim exports `/run/secrets/*` as env.
- No database, no admin UI, `store_model_in_db` off. The only credential is
  the per-box master key (`AGENTBOX_ROUTER_MASTER_KEY`, delivered to the
  router and to the agent).
- `general_settings.allowed_routes`: exactly the client routes of §5 P5.
  LiteLLM 1.102.1 `proxy/auth/auth_utils.py` `pre_db_read_auth_checks` (run by
  `_user_api_key_auth_builder` before the key check, so also for the master
  key) rejects any route not in the list with 403; the route is
  `scope["path"]` (exact string compare, no wildcard).
- `/v1/responses` (Codex) and `/v1/messages` (Claude) reach an OpenAI-
  compatible upstream as chat completions: `use_chat_completions_api: true`
  per deployment forces LiteLLM's Responses → chat bridge
  (`litellm/responses/main.py` `_bridges_to_chat_completions`); without it
  `hosted_vllm/` would call the upstream's own `/v1/responses`.
- Egress: the router allowlist is the host names of the `api_base` URLs
  (https, port 443 only; squid allows CONNECT to 443 only).
"""

from __future__ import annotations

import json
from urllib.parse import urlsplit

from . import compose, network
from .profile import Profile, hostname_problem

SERVICE = "router"
PORT = 4000
URL = f"http://{SERVICE}:{PORT}"
MASTER_KEY_ENV = "AGENTBOX_ROUTER_MASTER_KEY"
CONF_DIR = "/etc/router"
CONFIG_NAME = "config.yaml"
CONFIG_LABEL = "agentbox.router-config"
NO_PROXY = "localhost,127.0.0.1"
LIMITS = {"mem_limit": "1g", "pids_limit": 256}
# Exactly the client routes of PLAN §5 P5 (Claude: messages + count_tokens;
# Codex: responses; Pi / generic: chat completions; model list; healthcheck).
ALLOWED_ROUTES = [
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/v1/responses",
    "/v1/chat/completions",
    "/chat/completions",
    "/v1/models",
    "/models",
    "/health/liveliness",
]
PROVIDER_PREFIX = {"openai": "openai", "vllm": "hosted_vllm"}
LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "host.docker.internal", "gateway.docker.internal")
GUARD_CALLBACK = "agentbox_guard.guard"
NO_KEY = "agentbox-no-key"  # upstreams without auth; LiteLLM's openai client needs a value
HEALTH_ARGV = [
    "CMD",
    "python3", "-c",
    "import urllib.request,sys;"
    f"sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:{PORT}/health/liveliness',"
    "timeout=3).status==200 else 1)",
]  # fmt: skip


class RouterError(ValueError):
    pass


def _host(api_base: str) -> tuple[str, str, int | None]:
    u = urlsplit(api_base)
    try:
        port = u.port
    except ValueError:
        port = -1
    return u.scheme, (u.hostname or "").lower(), port


def check(profile: Profile) -> None:
    """Hard errors for remote models the router cannot reach through squid."""
    for m in profile.models.remote.values():
        where = f"models.remote.{m.name}.api_base"
        scheme, host, port = _host(m.api_base)
        if scheme != "https":
            raise RouterError(f"{where}: must use https:// (the router reaches remote models "
                              "only through the egress proxy, CONNECT to port 443)")  # fmt: skip
        if port not in (None, 443):
            raise RouterError(f"{where}: must use port 443")
        if host in LOCAL_HOSTS:
            raise RouterError(f"{where}: {host} is not reachable from the router; "
                              "host Ollama models use --model ollama/<m>")  # fmt: skip
        if msg := hostname_problem(host):
            raise RouterError(f"{where}: {host!r}: {msg}")


def config(profile: Profile) -> dict:
    check(profile)
    models = []
    for m in sorted(profile.models.remote.values(), key=lambda x: x.name):
        params = {
            "model": f"{PROVIDER_PREFIX[m.provider]}/{m.model}",
            "api_base": m.api_base,
            "api_key": f"os.environ/{m.key}" if m.key else NO_KEY,
            "use_chat_completions_api": True,
        }
        models.append({"model_name": m.name, "litellm_params": params})
    return {
        "model_list": models,
        "litellm_settings": {
            "drop_params": True,
            "request_timeout": 600,
            # Root-owned pre-call hook baked into the router image
            # (images/router/agentbox_guard.py): refuses header / key /
            # api_base injection, drops unknown request fields.
            "callbacks": [GUARD_CALLBACK],
        },
        "general_settings": {
            "master_key": f"os.environ/{MASTER_KEY_ENV}",
            # Never forward client HTTP headers upstream (the default; set
            # explicitly). LiteLLM 1.102.1 litellm_pre_call_utils.py
            # add_litellm_data_for_backend_llm_call forwards only when True.
            "forward_client_headers_to_llm_api": False,
            "store_model_in_db": False,
            "disable_spend_logs": True,
            "allowed_routes": list(ALLOWED_ROUTES),
        },
    }


def config_text(profile: Profile) -> str:
    return json.dumps(config(profile), indent=1, sort_keys=True) + "\n"


def egress_domains(profile: Profile) -> list[str]:
    return sorted({_host(m.api_base)[1] for m in profile.models.remote.values()})


def conf_dir(ctx: compose.Ctx):
    return ctx.state / SERVICE


def service(ctx: compose.Ctx) -> dict:
    ips = network.fixed_ips(ctx.n, ctx.base)
    env = {
        "HTTPS_PROXY": compose.PROXY,
        "HTTP_PROXY": compose.PROXY,
        "https_proxy": compose.PROXY,
        "http_proxy": compose.PROXY,
        "NO_PROXY": NO_PROXY,
        "no_proxy": NO_PROXY,
        "DISABLE_ADMIN_UI": "True",
        # Bundled model cost map: no fetch from GitHub at start.
        "LITELLM_LOCAL_MODEL_COST_MAP": "True",
        # httpx transport (honours HTTPS_PROXY) instead of the aiohttp one.
        "DISABLE_AIOHTTP_TRANSPORT": "True",
        "LITELLM_MODE": "PRODUCTION",  # no .env loading
    }
    return {
        "image": ctx.router_image,
        "init": True,
        "command": [
            "--config",
            f"{CONF_DIR}/{CONFIG_NAME}",
            "--port",
            str(PORT),
            "--num_workers",
            "1",
        ],  # fmt: skip
        "networks": {"internal": {"ipv4_address": ips[SERVICE]}},
        "environment": env,
        "volumes": [f"{conf_dir(ctx)}:{CONF_DIR}:ro"],
        "tmpfs": ["/tmp:mode=1777"],
        **compose.HARDEN,
        # No read_only: Compose refuses `secrets:` with an `environment:`
        # source on a read-only service (PLAN §2.1). The image runs as
        # uid 10003 (owns no image file); doctor 13 (router), 21 router-fs.
        **LIMITS,
        "healthcheck": {
            "test": HEALTH_ARGV,
            "interval": "10s",
            "timeout": "5s",
            "retries": 30,
            "start_period": "60s",
        },  # fmt: skip
        "labels": {CONFIG_LABEL: compose.config_hash({CONFIG_NAME: config_text(ctx.profile)})},
    }
