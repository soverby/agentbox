#!/bin/sh
# agentbox sidecar shim (PLAN §2.4): export each /run/secrets/<NAME> as NAME,
# then exec LiteLLM. Values are never printed.
# Reserved names (PLAN §2.4, the with-secrets list: PATH, LD_*, proxy vars,
# BASH_ENV, NODE_*, PYTHON*, GIT_*, TLS CA overrides, ...; any letter case)
# are never exported; only their count goes to stderr. Exception, as in
# with-secrets: MCP_GATEWAY_TOKEN, AGENTBOX_*, ANTHROPIC_* (the CLI delivers
# them as secrets).
set -eu
__s_skip=0
if [ -d /run/secrets ]; then
  for __s_f in /run/secrets/*; do
    [ -f "$__s_f" ] && [ ! -L "$__s_f" ] || continue
    __s_n=${__s_f##*/}
    case $__s_n in
      [A-Za-z_]*) ;;
      *) echo "router: bad secret name $__s_n" >&2; exit 2 ;;
    esac
    case $__s_n in *[!A-Za-z0-9_]*) echo "router: bad secret name $__s_n" >&2; exit 2 ;; esac
    __s_u=$(printf '%s' "$__s_n" | tr '[:lower:]' '[:upper:]')
    case $__s_u in
      __S_*|PATH|HOME|USER|SHELL|LD_*|*_PROXY|NPM_CONFIG_*|NODE_*|PYTHON*|\
      OLLAMA_HOST|DISABLE_AUTOUPDATER|DISABLE_UPDATES|\
      ENABLE_CLAUDEAI_MCP_SERVERS|CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC|\
      BASH_ENV|ENV|IFS|PS4|SSL_CERT_*|CURL_CA_BUNDLE|REQUESTS_CA_BUNDLE|GIT_*)
        __s_skip=$((__s_skip + 1)); continue ;;
    esac
    __s_v=$(cat "$__s_f")
    export "$__s_n=$__s_v"
  done
fi
if [ "$__s_skip" -gt 0 ]; then
  echo "router: skipped $__s_skip secret(s) with a reserved name" >&2
fi
unset __s_f __s_n __s_u __s_v __s_skip
exec litellm "$@"
