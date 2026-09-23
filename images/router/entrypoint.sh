#!/bin/sh
# agentbox sidecar shim (PLAN §2.4): export each /run/secrets/<NAME> as NAME
# (the router master key and the remote model keys that target the router),
# then exec LiteLLM. Values are never printed.
set -eu
if [ -d /run/secrets ]; then
  for f in /run/secrets/*; do
    [ -f "$f" ] || continue
    n=${f##*/}
    case $n in
      [A-Za-z_]*) ;;
      *) echo "router: bad secret name $n" >&2; exit 2 ;;
    esac
    case $n in *[!A-Za-z0-9_]*) echo "router: bad secret name $n" >&2; exit 2 ;; esac
    v=$(cat "$f")
    export "$n=$v"
  done
fi
unset f n v
exec litellm "$@"
