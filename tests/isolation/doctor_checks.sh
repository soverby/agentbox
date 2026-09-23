#!/usr/bin/env bash
# agentbox in-box isolation checks (PLAN §4): 1-9, 12, 13, 15, 18, 19.
# Runs inside the agent container (13 inside router / mcp-gateway).
# Needs: bash, curl, getent, jq. Prints "PASS n" or "FAIL n: reason" (or
# "SKIP n: reason") per check. Exit 1 if any check fails.
#
# Usage: doctor_checks.sh <check id>...
# Config (env, defaults in brackets):
#   DOCTOR_PROXY        [http://egress:3128]
#   DOCTOR_MODE         strict|open [strict]
#   DOCTOR_ROLE         agent|router|mcp-gateway [agent]
#   DOCTOR_ALLOWED      a domain on this source's allowlist [example.com]
#   DOCTOR_DENIED       a public domain NOT on this source's allowlist [example.org]
#   DOCTOR_MCP_PORTS    host MCP ports from the profile, space separated []
#   DOCTOR_BLOCKED_TCP  extra host:port targets that must not connect (4) []
#   DOCTOR_OTHER_TARGETS  host:port of another profile's containers (12) []
#   DOCTOR_PTR_IP       an IPv4 whose PTR name is on the allowlist (5) [1.1.1.1]
#   DOCTOR_PTR_NAME     that PTR name; must be allowlisted in strict mode [one.one.one.one]
#   DOCTOR_V6_NAMES     public names resolving (AAAA) to ::, ::1, ::a.b.c.d,
#                       ::ffff:<private>, ff00::/8, 2002::/16 (19)
#                       [the 0--0.sslip.io style names below]
#   DOCTOR_GATE         [http://ollama-gate:11434]
#   DOCTOR_GATE_MODEL   an allowed model (15) []
#   DOCTOR_GATE_DENIED_MODEL  a model that must be denied (15) [agentbox-not-a-model:1]
#   DOCTOR_GATE_CLOUD_MODEL   a cloud model name (15) [gpt-oss:120b-cloud]
#
# Check 5 note: DOCTOR_PTR_NAME must be allowlisted (strict) and be the PTR of
# DOCTOR_PTR_IP; the check first proves the name itself gets 200, so a
# missing `-n` or ip_literal deny makes the IP forms return 200 and fail.
# Check 19 uses sslip.io names that resolve (AAAA) to ::, ::1,
# ::8.8.8.8, ::ffff:10.1.2.3, ff02::1 and 2002:a01:203::1.
set -u
P=${DOCTOR_PROXY:-http://egress:3128}
MODE=${DOCTOR_MODE:-strict}
ROLE=${DOCTOR_ROLE:-agent}
ALLOWED=${DOCTOR_ALLOWED:-example.com}
DENIED=${DOCTOR_DENIED:-example.org}
MCP_PORTS=${DOCTOR_MCP_PORTS:-}
GATE=${DOCTOR_GATE:-http://ollama-gate:11434}
GMODEL=${DOCTOR_GATE_MODEL:-}
GDENIED=${DOCTOR_GATE_DENIED_MODEL:-agentbox-not-a-model:1}
GCLOUD=${DOCTOR_GATE_CLOUD_MODEL:-gpt-oss:120b-cloud}
RC=0

# Per-check failure list; a check passes when it collects no reason.
REASONS=()
bad() { REASONS+=("$*"); }
report() {
  if [ ${#REASONS[@]} -eq 0 ]; then echo "PASS $1"
  else echo "FAIL $1: $(IFS='; '; echo "${REASONS[*]}")"; RC=1; fi
  REASONS=()
}

# CONNECT status code from the proxy for host:port ("000" = no answer).
connect_code() {
  curl -s -o /dev/null -x "$P" --noproxy '' --connect-timeout 5 -m 15 -w '%{http_connect}' "https://$1/" 2>/dev/null
}
# Status of a plain-HTTP forward request through the proxy.
plain_code() {
  curl -s -o /dev/null -x "$P" --noproxy '' --connect-timeout 5 -m 15 -w '%{http_code}' "http://$1" 2>/dev/null
}
expect_connect() {  # host:port expected-code
  local c; c=$(connect_code "$1"); [ "$c" = "$2" ] || bad "CONNECT $1 -> $c (want $2)"
}
expect_plain() {
  local c; c=$(plain_code "$1"); [ "$c" = "$2" ] || bad "GET http://$1 -> $c (want $2)"
}
tcp_fails() {  # host port
  if timeout 4 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; then bad "TCP $1:$2 connected"; fi
}

check_1() {
  if curl -s -o /dev/null --noproxy '*' --connect-timeout 5 -m 10 https://example.com; then
    bad "direct https://example.com succeeded"
  fi
  if awk 'NR>1 && $2=="00000000" {f=1} END {exit !f}' /proc/net/route; then
    bad "default route present"
  fi
  report 1
}

check_2() {
  if [ "$MODE" != strict ]; then echo "SKIP 2: mode is $MODE"; return; fi
  expect_connect "$DENIED:443" 403
  report 2
}

check_3() {
  expect_connect "$ALLOWED:443" 200
  local c; c=$(curl -s -o /dev/null -x "$P" -m 20 -w '%{http_code}' "https://$ALLOWED/")
  case "$c" in 2??|3??) ;; *) bad "GET https://$ALLOWED/ -> $c" ;; esac
  report 3
}

check_4() {
  local t
  for t in 1.1.1.1:443 8.8.8.8:53 169.254.169.254:80 192.168.65.1:80 192.168.65.254:80 \
           192.168.65.254:11434 192.168.65.7:2375 ${DOCTOR_BLOCKED_TCP:-}; do
    tcp_fails "${t%:*}" "${t##*:}"
  done
  report 4
}

check_5() {
  local ip=${DOCTOR_PTR_IP:-1.1.1.1} name=${DOCTOR_PTR_NAME:-one.one.one.one}
  local ptr a b c d dec hex t
  ptr=$(getent hosts "$ip" 2>/dev/null | awk '{print $2}')  # no DNS in box: usually empty
  expect_connect "$name:443" 200  # precondition: the PTR name itself is allowed
  IFS=. read -r a b c d <<<"$ip"
  dec=$(( (a << 24) + (b << 16) + (c << 8) + d ))
  hex=$(printf '0x%08x' "$dec")
  for t in "$ip:443" "$dec:443" "$hex:443" '[2606:4700:4700::1111]:443' 8.8.8.8:443; do
    expect_connect "$t" 403
  done
  for t in "$ip/" "$dec/" '[2606:4700:4700::1111]/' 8.8.8.8:443/; do
    expect_plain "$t" 403
  done
  [ -z "$ptr" ] || [ "$ptr" = "$name" ] || bad "PTR of $ip is $ptr, not $name"
  report 5
}

check_6() {
  local n
  for n in example.com "$ALLOWED" host.docker.internal gateway.docker.internal; do
    if getent hosts "$n" >/dev/null 2>&1; then bad "getent hosts $n answered"; fi
    if getent ahosts "$n" >/dev/null 2>&1; then bad "getent ahosts $n answered"; fi
  done
  report 6
}

check_7() {
  local h p
  for h in host.docker.internal gateway.docker.internal; do
    for p in 443 80 11434 22 $MCP_PORTS; do
      expect_connect "$h:$p" 403
      expect_plain "$h:$p/" 403
    done
  done
  report 7
}

check_8() {
  expect_connect "$ALLOWED:22" 403
  expect_connect "$ALLOWED:80" 403
  expect_connect "$ALLOWED:8443" 403
  local proxy_hp=${P#http://}
  local c
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' "http://$proxy_hp/squid-internal-mgr/menu")
  [ "$c" = 403 ] || bad "direct cache manager -> $c (want 403)"
  c=$(curl -s -o /dev/null -x "$P" -m 10 -w '%{http_code}' "http://$proxy_hp/squid-internal-mgr/menu")
  [ "$c" = 403 ] || bad "proxied cache manager -> $c (want 403)"
  report 8
}

check_9() {
  local s
  for s in /var/run/docker.sock /run/docker.sock; do [ -e "$s" ] && bad "$s exists"; done
  for f in CapEff CapBnd CapPrm CapAmb; do
    v=$(awk -v k="$f:" '$1==k {print $2}' /proc/self/status)
    [ "$v" = 0000000000000000 ] || bad "$f=$v"
  done
  [ "$(awk '$1=="NoNewPrivs:" {print $2}' /proc/self/status)" = 1 ] || bad "NoNewPrivs not set"
  [ "$(id -u)" != 0 ] || bad "running as root"
  report 9
}

check_12() {
  local t
  if [ -z "${DOCTOR_OTHER_TARGETS:-}" ]; then echo "SKIP 12: no other profile"; return; fi
  for t in $DOCTOR_OTHER_TARGETS; do
    tcp_fails "${t%:*}" "${t##*:}"
    c=$(connect_code "$t"); [ "$c" = 403 ] || bad "CONNECT $t -> $c (want 403)"
  done
  report 12
}

check_13() {
  if curl -s -o /dev/null --noproxy '*' --connect-timeout 5 -m 10 "https://$ALLOWED/"; then
    bad "$ROLE: direct egress succeeded"
  fi
  expect_connect "$ALLOWED:443" 200
  expect_connect "$DENIED:443" 403
  expect_connect "1.1.1.1:443" 403
  local p c
  for p in $MCP_PORTS; do
    c=$(plain_code "host.docker.internal:$p/")
    if [ "$ROLE" = mcp-gateway ]; then
      [ "$c" = 200 ] || bad "gateway GET host MCP :$p -> $c (want 200)"
    else
      [ "$c" = 403 ] || bad "$ROLE GET host MCP :$p -> $c (want 403)"
    fi
    expect_connect "host.docker.internal:$p" 403
  done
  report "13 ($ROLE)"
}

# ---- ollama-gate
gate_post() {  # path body [extra curl args...] -> status
  local path=$1 body=$2; shift 2
  curl -s -o /dev/null --noproxy '*' -m 20 -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' "$@" --data-binary "$body" "$GATE$path"
}
is_4xx() { case "$1" in 4??) return 0 ;; *) return 1 ;; esac; }

check_15() {
  local gh=${GATE#http://}; gh=${gh%%:*}
  local gp=${GATE##*:}
  local p c open=()
  for p in $(seq 1 1024) 2375 3128 4000 8000 8080 8443 11433 11435; do
    if timeout 1 bash -c "exec 3<>/dev/tcp/$gh/$p" 2>/dev/null; then open+=("$p"); fi
  done
  [ ${#open[@]} -eq 0 ] || bad "extra open ports on $gh: ${open[*]}"
  timeout 2 bash -c "exec 3<>/dev/tcp/$gh/$gp" 2>/dev/null || bad "port $gp not open"
  if [ -z "$GMODEL" ]; then bad "DOCTOR_GATE_MODEL not set"; report 15; return; fi
  local ok="{\"model\":\"$GMODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}"
  for p in /api/pull /api/copy /api/create /api/push /api/blobs/sha256:00 \
           /v1/responses/compact /api/me /api/experimental/web_fetch /api/chat/ /API/chat; do
    c=$(gate_post "$p" "$ok"); [ "$c" = 403 ] || bad "POST $p -> $c (want 403)"
  done
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' -X DELETE \
      -H 'Content-Type: application/json' --data "{\"model\":\"$GMODEL\"}" "$GATE/api/delete")
  [ "$c" = 403 ] || bad "DELETE /api/delete -> $c"
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' -I "$GATE/api/blobs/sha256:00")
  [ "$c" = 403 ] || bad "HEAD /api/blobs -> $c"
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' \
      -F "model=$GMODEL" -F "file=@/etc/hostname" "$GATE/v1/audio/transcriptions")
  [ "$c" = 403 ] || bad "multipart /v1/audio/transcriptions -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GDENIED\",\"messages\":[]}"); [ "$c" = 403 ] || bad "denied model -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GCLOUD\",\"messages\":[]}"); [ "$c" = 403 ] || bad "cloud model -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GMODEL:cloud\",\"messages\":[]}"); [ "$c" = 403 ] || bad ":cloud suffix -> $c"
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' "$GATE/v1/models/$GDENIED")
  [ "$c" = 403 ] || bad "GET /v1/models/<denied> -> $c"
  c=$(gate_post /api/chat "{\"MODEL\":\"$GDENIED\"}"); is_4xx "$c" || bad "MODEL key -> $c"
  c=$(gate_post /api/chat "{\"Model\":\"$GMODEL\"}"); is_4xx "$c" || bad "Model key -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GMODEL\",\"model\":\"$GDENIED\"}"); is_4xx "$c" || bad "duplicate model -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GMODEL\",\"mOdEl\":\"$GDENIED\"}"); is_4xx "$c" || bad "model+mOdEl -> $c"
  c=$(gate_post /api/show "{\"name\":\"$GMODEL\",\"model\":\"$GDENIED\"}"); is_4xx "$c" || bad "show name+model -> $c"
  c=$(gate_post /api/chat "{\"model\":\"$GMODEL\",\"x\":NaN}"); is_4xx "$c" || bad "NaN -> $c"
  c=$(gate_post /api/chat "[\"$GMODEL\"]"); is_4xx "$c" || bad "non-object -> $c"
  c=$(printf '%s' "$ok" | curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' \
      -H 'Content-Type: application/json' -H 'Transfer-Encoding: chunked' --data-binary @- "$GATE/api/chat")
  is_4xx "$c" || bad "chunked body -> $c"
  c=$(gate_post /api/chat "$ok" -H 'Content-Encoding: gzip'); is_4xx "$c" || bad "Content-Encoding -> $c"
  c=$(gate_post /api/chat "$ok" -H 'Content-Type: text/plain'); is_4xx "$c" || bad "text/plain -> $c"
  c=$(gate_post /api/chat "$ok" -H 'Content-Type: application/x-www-form-urlencoded'); is_4xx "$c" || bad "form -> $c"
  c=$(gate_post /api/show "{\"model\":\"$GMODEL\"}"); [ "$c" = 200 ] || bad "show allowed -> $c"
  c=$(curl -s -o /dev/null --noproxy '*' -m 10 -w '%{http_code}' "$GATE/api/tags"); [ "$c" = 200 ] || bad "tags -> $c"
  # allowed chat: 200, chunked, several NDJSON lines, first byte before the end
  local out hdr
  out=$(mktemp); hdr=$(mktemp)
  local w
  w=$(curl -sN --noproxy '*' -m 300 -D "$hdr" -o "$out" -w '%{http_code} %{time_starttransfer} %{time_total}' \
      -H 'Content-Type: application/json' --data-binary "$ok" "$GATE/api/chat")
  set -- $w
  [ "$1" = 200 ] || bad "allowed chat -> $1"
  grep -qi '^transfer-encoding: *chunked' "$hdr" || bad "response not chunked"
  [ "$(grep -c . "$out")" -ge 2 ] || bad "fewer than 2 stream lines"
  awk -v s="$2" -v t="$3" 'BEGIN {exit !(t - s > 0.2)}' || bad "not streamed (start $2 s, total $3 s)"
  rm -f "$out" "$hdr"
  report 15
}

check_18() {
  local v tags n rh c
  v=$(curl -s --noproxy '*' -m 10 "$GATE/api/version" | jq -r .version)
  if [ -z "$v" ] || [ "$v" = null ]; then bad "no version"
  elif [ "$(printf '%s\n0.14.0\n' "$v" | sort -V | head -1)" != 0.14.0 ]; then bad "Ollama $v < 0.14.0"; fi
  tags=$(curl -s --noproxy '*' -m 10 "$GATE/api/tags")
  while IFS=$'\t' read -r n rh; do
    [ -n "$n" ] || continue
    c=$(gate_post /api/show "{\"model\":\"$n\"}")
    if [ -n "$rh" ]; then
      [ "$c" = 403 ] || bad "cloud model $n (remote_host $rh) allowed: /api/show -> $c"
    elif [ "$c" = 200 ]; then
      rh=$(curl -s --noproxy '*' -m 10 -H 'Content-Type: application/json' \
           --data "{\"model\":\"$n\"}" "$GATE/api/show" | jq -r '.remote_host // ""')
      [ -z "$rh" ] || bad "allowed model $n has remote_host $rh"
    fi
  done < <(printf '%s' "$tags" | jq -r '.models[] | [.name, (.remote_host // "")] | @tsv')
  report 18
}

check_19() {
  if [ "$MODE" != open ]; then echo "SKIP 19: mode is $MODE"; return; fi
  expect_connect "$ALLOWED:443" 200
  expect_connect "$DENIED:443" 200
  local t
  for t in 1.1.1.1 10.0.0.1 172.16.0.1 192.168.1.1 127.0.0.1 169.254.169.254 100.64.0.1 \
           '[::1]' '[fe80::1]' '[fd00::1]' host.docker.internal gateway.docker.internal \
           10.0.0.1.nip.io 127.0.0.1.sslip.io 169.254.169.254.nip.io 192.168.65.254.nip.io \
           egress ollama-gate localhost; do
    expect_connect "$t:443" 403
  done
  expect_plain "169.254.169.254/latest/meta-data/" 403
  report 19
  check_19_v6
}

# Names that resolve only to non-public IPv6 addresses. Docker Desktop's DNS
# returns no AAAA records, so first probe the canary (the first name): squid
# 503 with X-Squid-Error ERR_DNS_FAIL means "no address" -> SKIP. Any other
# answer runs every name and requires 403 (a connect failure, 503
# ERR_CONNECT_FAIL, means the deny rule is missing -> FAIL).
V6_DEFAULT="0--0.sslip.io 0--1.sslip.io 0--808-808.sslip.io 0--ffff-a01-203.sslip.io \
ff02--1.sslip.io 2002-a01-203--1.sslip.io 100--1.sslip.io 2001--1.sslip.io \
2001-db8--1.sslip.io 64-ff9b-1--1.sslip.io fec0--1.sslip.io"
check_19_v6() {
  local names=${DOCTOR_V6_NAMES:-$V6_DEFAULT} canary out code err t
  canary=${names%% *}
  out=$(curl -sv -o /dev/null -x "$P" --noproxy '' --connect-timeout 5 -m 15 \
        -w 'CODE=%{http_connect}\n' "https://$canary/" 2>&1)
  code=$(printf '%s\n' "$out" | sed -n 's/^CODE=//p')
  err=$(printf '%s\n' "$out" | tr -d '\r' | sed -n 's/^< [Xx]-[Ss]quid-[Ee]rror: \([A-Z_]*\).*/\1/p' | head -1)
  if [ "$code" = 503 ] && [ "$err" = ERR_DNS_FAIL ]; then
    echo "SKIP 19-v6: no IPv6 resolution from egress ($canary: ERR_DNS_FAIL)"
    return
  fi
  for t in $names; do expect_connect "$t:443" 403; done
  report 19-v6
}

[ $# -gt 0 ] || set -- 1 2 3 4 5 6 7 8 9 12 15 18 19
for id in "$@"; do
  if declare -F "check_$id" >/dev/null; then "check_$id"; else echo "FAIL $id: unknown check"; RC=1; fi
done
exit $RC
