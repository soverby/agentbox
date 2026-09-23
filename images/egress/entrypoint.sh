#!/bin/sh
# Start squid in the foreground with the agentbox config. Runs as user proxy
# (uid 13) with no capabilities; the log dir must be writable by uid 13.
# Reload after a config change:
#   docker exec <egress> squid -k reconfigure -f /etc/squid/agentbox/squid.conf
set -eu
CONF=/etc/squid/agentbox/squid.conf
/usr/sbin/squid -k parse -f "$CONF"
exec /usr/sbin/squid -f "$CONF" -NYC
