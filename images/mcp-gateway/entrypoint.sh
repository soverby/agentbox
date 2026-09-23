#!/bin/sh
# agentbox sidecar shim (PLAN §2.4): export each /run/secrets/<NAME> as NAME,
# then exec the gateway. gateway.py removes these names from its own env at
# start, so stdio servers it spawns never inherit them.
set -eu
if [ -d /run/secrets ]; then
  for f in /run/secrets/*; do
    [ -f "$f" ] || continue
    n=${f##*/}
    case $n in
      [A-Za-z_]*) ;;
      *) echo "mcp-gateway: bad secret name $n" >&2; exit 2 ;;
    esac
    case $n in *[!A-Za-z0-9_]*) echo "mcp-gateway: bad secret name $n" >&2; exit 2 ;; esac
    v=$(cat "$f")
    export "$n=$v"
  done
fi
exec python3 /opt/mcp-gateway/gateway.py "$@"
