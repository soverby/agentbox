#!/bin/sh
# Start squid in the foreground with the agentbox config. Runs as user proxy
# (uid 13) with no capabilities; the log dir must be writable by uid 13.
# Reload after a config change:
#   docker exec <egress> squid -k reconfigure -f /etc/squid/agentbox/squid.conf
#
# Log size guard (PLAN §2.6): every AGENTBOX_LOG_EVERY s, an egress.log above
# AGENTBOX_LOG_MAX bytes becomes egress.log.1 (one old file kept) and squid
# reopens its logs (`squid -k rotate`; logfile_rotate 0 = reopen only). If the
# log is still above AGENTBOX_LOG_HARD after that (rotation failed or did not
# keep up), the loop truncates it. The loop is a child of squid (exec below).
set -eu
CONF=/etc/squid/agentbox/squid.conf
LOG=/var/log/agentbox/egress.log
EVERY=${AGENTBOX_LOG_EVERY:-15}
MAX=${AGENTBOX_LOG_MAX:-20971520}
HARD=${AGENTBOX_LOG_HARD:-31457280}
/usr/sbin/squid -k parse -f "$CONF"

size() { stat -c %s "$1" 2>/dev/null || echo 0; }

guard() {
  set +e
  while :; do
    sleep "$EVERY"
    n=$(size "$LOG")
    if [ "$n" -gt "$MAX" ]; then
      mv -f "$LOG" "$LOG.1" && /usr/sbin/squid -k rotate -f "$CONF" >/dev/null 2>&1
      if [ "$(size "$LOG")" -gt "$HARD" ]; then
        truncate -s 0 "$LOG"
        echo "agentbox-egress: egress.log above $HARD bytes after rotation; truncated" >&2
      fi
    fi
    # squid may still write to the renamed file until it reopens.
    if [ "$(size "$LOG.1")" -gt "$HARD" ]; then
      truncate -s 0 "$LOG.1"
      echo "agentbox-egress: egress.log.1 above $HARD bytes; truncated" >&2
    fi
  done
}
guard </dev/null &
exec /usr/sbin/squid -f "$CONF" -NYC
