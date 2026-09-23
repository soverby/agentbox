#!/usr/bin/env bash
# P1 gate for the agent image (docs/PLAN.md §5 P1, doctor 16).
# Runs checks in a container started with the §2.1 runtime hardening and an
# empty named volume at /home/agent. Prints PASS/FAIL per check; exits 1 on
# any FAIL.
set -uo pipefail
here=$(cd "$(dirname "$0")" && pwd)
IMAGE=${IMAGE:-agentbox/agent:latest}
PY_PIN=$(sed -n 's/^PYTHON_VERSION=//p' "$here/versions.env")
[ -n "$PY_PIN" ] || { echo "PYTHON_VERSION missing from versions.env" >&2; exit 2; }

run_id="agentbox-p1-test-$$"
vol="${run_id}-home"
secrets=$(mktemp -d "${TMPDIR:-/tmp}/agentbox-p1-secrets.XXXXXX")
fails=0
cleanup() {
  docker rm -f "$run_id" "${run_id}-nosecrets" >/dev/null 2>&1
  docker volume rm -f "$vol" >/dev/null 2>&1
  rm -rf "$secrets"
}
trap cleanup EXIT

HARDEN=(--cap-drop ALL --security-opt no-new-privileges:true --user 1000 --network none)

# Test secrets: good names, trailing-newline cases, bad names, a reserved name.
printf 'value-one\n'        > "$secrets/GOOD_ONE"      # one trailing NL: stripped
printf 'two\n\n'            > "$secrets/TWO_NL"        # only ONE NL stripped
printf 'no-newline'         > "$secrets/_NO_NL"
printf 'a b\n  c\t$HOME`x`' > "$secrets/MULTI"         # spaces, inner NL, no expansion
printf 'bad\n'              > "$secrets/bad-name"
printf 'bad\n'              > "$secrets/1BAD"
printf '/evil\n'            > "$secrets/PATH"          # reserved: never exported
printf 'http://evil:1\n'    > "$secrets/https_proxy"   # reserved (any case)
printf '/run/secrets/evil.sh\n' > "$secrets/BASH_ENV"    # reserved: must not be sourced
printf 'echo PWNED\n'       > "$secrets/evil.sh"       # bad name; BASH_ENV target
printf '/tmp\n'             > "$secrets/GIT_DIR"       # reserved
printf '/x\n'               > "$secrets/NODE_EXTRA_CA_CERTS" # reserved
printf 'x\n'                > "$secrets/Env"           # reserved (any case)
head -c 140000 /dev/zero | tr '\0' 'A' > "$secrets/A_BIG"  # > 128 KiB: skipped + warning
printf 'after-big\n'        > "$secrets/B_AFTER"       # sorts after A_BIG: still exported
mkdir "$secrets/DIRNAME"                               # not a regular file
ln -s GOOD_ONE "$secrets/LINKED"                       # symlink: skipped
chmod 0644 "$secrets"/* ; chmod 0755 "$secrets" "$secrets/DIRNAME"

docker volume create "$vol" >/dev/null
docker run -d --name "$run_id" "${HARDEN[@]}" \
  -v "$vol:/home/agent" -v "$secrets:/run/secrets:ro" \
  -e PI_OFFLINE=1 "$IMAGE" >/dev/null || { echo "FAIL: container start"; exit 1; }

ex() { docker exec "$run_id" "$@"; }
check() { # name, command...
  local name=$1; shift
  local out
  if out=$("$@" 2>&1); then
    printf 'PASS  %-34s %s\n' "$name" "$(printf '%s' "$out" | head -n1)"
  else
    printf 'FAIL  %-34s %s\n' "$name" "$(printf '%s' "$out" | tr '\n' ' ' | cut -c1-300)"
    fails=$((fails + 1))
  fi
}

# --- versions -------------------------------------------------------------
check "claude --version >= 2.1.246" bash -c '
  v=$(docker exec '"$run_id"' claude --version) || exit 1; echo "$v"
  n=${v%% *}; IFS=. read -r a b c <<<"$n"
  [ "$a" -gt 2 ] || { [ "$a" -eq 2 ] && { [ "$b" -gt 1 ] || { [ "$b" -eq 1 ] && [ "$c" -ge 246 ]; }; }; }'
check "codex --version"  ex codex --version
check "pi --version"     ex pi --version
check "ollama --version (client)" bash -c "docker exec $run_id ollama --version 2>&1 | grep -E 'client version is [0-9]'"
check "gh --version"     ex gh --version
check "jq --version"     ex jq --version
check "python == $PY_PIN" bash -c "o=\$(docker exec $run_id python --version) && echo \"\$o\" && [ \"\$o\" = 'Python $PY_PIN' ] && [ \"\$(docker exec $run_id python3 --version)\" = 'Python $PY_PIN' ]"
check "uv --version"     ex uv --version

# --- users / privileges ---------------------------------------------------
check "id is agent 1000" bash -c "o=\$(docker exec $run_id id) && echo \"\$o\" && [ \"\$o\" = 'uid=1000(agent) gid=1000(agent) groups=1000(agent)' ]"
check "no ubuntu user"   bash -c "! docker exec $run_id getent passwd ubuntu && echo absent"
check "no sudo"          bash -c "! docker exec $run_id sh -c 'command -v sudo || ls /usr/bin/sudo /etc/sudoers' && echo absent"
check "CapEff/CapBnd = 0" bash -c "o=\$(docker exec $run_id grep -E '^Cap(Eff|Bnd)' /proc/self/status) && echo \$o && ! echo \"\$o\" | grep -qv '0000000000000000'"

# --- doctor 16 --------------------------------------------------------------
# PATH entries under /home/agent (~/.npm-global/bin, ~/.local/bin) live in the
# per-profile home volume and are writable by design (user-space npm -g,
# uv tool). They come AFTER every system dir in PATH, so they cannot shadow a
# system binary, and the CLI runs with-secrets by absolute path. They are
# excluded here and listed for the record.
check "doctor16: no writable system path" bash -c "
  o=\$(docker exec $run_id sh -c '
    dirs=\"/usr /etc /opt\"; for p in \$(echo \"\$PATH\" | tr : \" \"); do dirs=\"\$dirs \$p\"; done
    for d in \$dirs; do [ -e \"\$d\" ] && find \"\$d\" -writable 2>/dev/null; done | sort -u') || exit 1
  bad=\$(printf '%s\n' \"\$o\" | grep -v '^\$' | grep -v '^/home/agent\(/\|\$\)')
  home=\$(printf '%s\n' \"\$o\" | grep -c '^/home/agent')
  if [ -n \"\$bad\" ]; then echo \"writable: \$bad\"; exit 1; fi
  echo \"none (excluded \$home path(s) under /home/agent)\""
check "doctor16: PATH home dirs after system" bash -c "
  p=\$(docker exec $run_id sh -c 'echo \$PATH') && echo \"\$p\" &&
  echo \"\$p\" | grep -Eq '^(/[^:]*:)*/bin(:/home/agent/[^:]*)+\$'"
check "managed-mcp.json root 0644, ro" bash -c "
  o=\$(docker exec $run_id stat -c '%U:%G %a' /etc/claude-code/managed-mcp.json /etc/claude-code) && echo \$o &&
  [ \"\$o\" = \"\$(printf 'root:root 644\nroot:root 755')\" ] &&
  ! docker exec $run_id sh -c 'test -w /etc/claude-code/managed-mcp.json || test -w /etc/claude-code' &&
  ! docker exec $run_id sh -c ': >> /etc/claude-code/managed-mcp.json' 2>/dev/null"
check "managed-mcp.json content" bash -c "
  docker exec $run_id jq -e '(.mcpServers|keys)==[\"agentbox\"] and .mcpServers.agentbox.type==\"http\" and .mcpServers.agentbox.url==\"http://mcp-gateway:8080/mcp\" and .mcpServers.agentbox.headers.Authorization==\"Bearer \${MCP_GATEWAY_TOKEN}\"' /etc/claude-code/managed-mcp.json"
check "with-secrets root 0755" bash -c "o=\$(docker exec $run_id stat -c '%U:%G %a' /usr/local/bin/with-secrets) && echo \$o && [ \"\$o\" = 'root:root 755' ]"

# --- no GPU libs ------------------------------------------------------------
check "no GPU libs" bash -c "
  o=\$(docker exec $run_id sh -c \"find / -xdev \\( -name 'libcuda*' -o -name 'libcublas*' -o -name '*rocm*' \\) 2>/dev/null\")
  [ -z \"\$o\" ] && echo none || { echo \"\$o\"; exit 1; }"

# --- env ------------------------------------------------------------------
check "agent env" bash -c "
  docker exec $run_id sh -c '
    [ \"\$HTTPS_PROXY\" = http://egress:3128 ] && [ \"\$HTTP_PROXY\" = http://egress:3128 ] &&
    [ \"\$https_proxy\" = http://egress:3128 ] && [ \"\$http_proxy\" = http://egress:3128 ] &&
    [ \"\$NO_PROXY\" = router,mcp-gateway,ollama-gate,localhost,127.0.0.1 ] && [ \"\$no_proxy\" = \"\$NO_PROXY\" ] &&
    [ \"\$OLLAMA_HOST\" = http://ollama-gate:11434 ] && [ \"\$NPM_CONFIG_PREFIX\" = /home/agent/.npm-global ] &&
    [ \"\$DISABLE_AUTOUPDATER\" = 1 ] && [ \"\$DISABLE_UPDATES\" = 1 ] &&
    [ \"\$CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC\" = 1 ] && [ \"\$ENABLE_CLAUDEAI_MCP_SERVERS\" = false ] &&
    echo ok'"

# --- with-secrets -----------------------------------------------------------
# Each value is hex-dumped so exact bytes (incl. newlines) are compared.
hexof() { docker exec "$run_id" /usr/local/bin/with-secrets 2>/dev/null sh -c "printf '%s' \"\${$1-UNSET}\" | od -An -tx1 | tr -d ' \n'"; }
hexlit() { printf '%b' "$1" | od -An -tx1 | tr -d ' \n'; }
ws_eq() { local got want; got=$(hexof "$1") || return 1; want=$(hexlit "$2"); [ "$got" = "$want" ] && echo "$1 ok" || { echo "$1 got=$got want=$want"; return 1; }; }
check "with-secrets GOOD_ONE (1 NL cut)" ws_eq GOOD_ONE 'value-one'
check "with-secrets TWO_NL (only 1 cut)"  ws_eq TWO_NL   'two\n'
check "with-secrets _NO_NL"               ws_eq _NO_NL   'no-newline'
check "with-secrets MULTI (exact bytes)"  ws_eq MULTI    'a b\n  c\t$HOME`x`'
check "with-secrets skips bad/link/dir" bash -c "
  o=\$(docker exec $run_id /usr/local/bin/with-secrets 2>/dev/null sh -c 'env | cut -d= -f1 | grep -E \"^(bad|1BAD|LINKED|DIRNAME)\$\"'); [ -z \"\$o\" ] && echo skipped || { echo \"\$o\"; exit 1; }"
check "with-secrets never sets reserved" bash -c "
  docker exec $run_id /usr/local/bin/with-secrets 2>/dev/null sh -c '[ \"\$PATH\" != /evil ] && [ \"\$https_proxy\" = http://egress:3128 ] && echo kept'"
check "with-secrets prints only big warning" bash -c "
  o=\$(docker exec $run_id /usr/local/bin/with-secrets true 2>&1) &&
  [ \"\$o\" = 'with-secrets: skipped A_BIG (larger than 128 KiB)' ] && echo \"\$o\""
check "with-secrets skips >128KiB, goes on" bash -c "
  docker exec $run_id /usr/local/bin/with-secrets sh -c '[ -z \"\${A_BIG+x}\" ] && [ \"\$B_AFTER\" = after-big ] && echo ok' 2>/dev/null"
check "with-secrets BASH_ENV not sourced" bash -c "
  o=\$(docker exec $run_id /usr/local/bin/with-secrets bash -c 'echo \"ok:\${BASH_ENV-unset}\"' 2>/dev/null) &&
  [ \"\$o\" = ok:unset ] && echo \"\$o\" &&
  [ \"\$(docker exec -e BASH_ENV=/run/secrets/evil.sh $run_id bash -c 'echo ok')\" = \"\$(printf 'PWNED\\nok')\" ] &&
  echo '(control: BASH_ENV set directly is sourced)'"
check "with-secrets refuses GIT_/NODE_/Env" bash -c "
  o=\$(docker exec $run_id /usr/local/bin/with-secrets env 2>/dev/null | cut -d= -f1 | grep -E '^(GIT_DIR|NODE_EXTRA_CA_CERTS|Env)\$'); [ -z \"\$o\" ] && echo refused || { echo \"\$o\"; exit 1; }"
check "with-secrets passes argv + exit" bash -c "
  o=\$(docker exec $run_id /usr/local/bin/with-secrets 2>/dev/null printf '%s|' 'a b' '' c) && [ \"\$o\" = 'a b||c|' ] &&
  docker exec $run_id /usr/local/bin/with-secrets 2>/dev/null sh -c 'exit 7'; [ \$? -eq 7 ] && echo ok"
check "with-secrets no /run/secrets = noop" bash -c "
  docker run --rm --name ${run_id}-nosecrets ${HARDEN[*]} $IMAGE /usr/local/bin/with-secrets sh -c '[ ! -e /run/secrets ] && [ -z \"\${GOOD_ONE-}\" ] && echo noop'"

# --- Pi finds pi-mcp-adapter with an empty home volume ---------------------
# The adapter registers the --mcp-config flag; Pi lists extension flags in
# --help. Control: the bare Pi CLI (no wrapper) must NOT show it.
check "pi loads pi-mcp-adapter" bash -c "
  docker exec $run_id sh -c 'ls -A /home/agent/.pi/agent/extensions 2>/dev/null; test ! -e /home/agent/.pi/agent/settings.json' &&
  docker exec $run_id pi --help 2>&1 | grep -E -- '--mcp-config' &&
  ! docker exec $run_id node /usr/local/lib/node_modules/@earendil-works/pi-coding-agent/dist/bundle/cli.js --help 2>&1 | grep -q -- '--mcp-config'"
check "pi-mcp-adapter version pinned" bash -c "
  v=\$(docker exec $run_id jq -r .version /usr/local/lib/agentbox/pi-mcp-adapter/node_modules/pi-mcp-adapter/package.json) && echo \$v &&
  [ \"\$v\" = \"\$(sed -n 's/^PI_MCP_ADAPTER_VERSION=//p' '$here/versions.env')\" ]"

check "adapter tree == committed lockfile" bash -c "
  docker exec $run_id sh -c 'cd /usr/local/lib/agentbox/pi-mcp-adapter && cat package-lock.json' |
    cmp - '$here/pi-mcp-adapter/package-lock.json' &&
  docker exec $run_id sh -c 'cd /usr/local/lib/agentbox/pi-mcp-adapter && jq -r \".packages|to_entries[]|select(.key!=\\\"\\\" and (.value.optional|not))|.key+\\\" \\\"+.value.version\" package-lock.json | while read -r k v; do
      [ \"\$(jq -r .version \$k/package.json)\" = \"\$v\" ] || { echo \"mismatch \$k\"; exit 1; }; done; echo match'"
check "sbom-npm.txt root 0644" bash -c "
  o=\$(docker exec $run_id stat -c '%U:%G %a' /usr/local/share/agentbox/sbom-npm.txt) && echo \"\$o\" && [ \"\$o\" = 'root:root 644' ] &&
  docker exec $run_id grep -c -E '(@openai/codex|pi-coding-agent|pi-mcp-adapter)@' /usr/local/share/agentbox/sbom-npm.txt >/dev/null"
check "doctor16: no setuid/setgid files" bash -c "
  o=\$(docker exec $run_id find / -xdev -perm /6000 -type f 2>/dev/null); [ -z \"\$o\" ] && echo none || { echo \"\$o\"; exit 1; }"
check "pip install --user (offline wheel)" bash -c "
  docker exec $run_id sh -c '
    set -e; d=\$(mktemp -d); cd \$d
    python - <<PY
import zipfile
n=\"agentbox_probe-0.1.dist-info\"
with zipfile.ZipFile(\"agentbox_probe-0.1-py3-none-any.whl\",\"w\") as z:
    z.writestr(\"agentbox_probe.py\",\"OK = 42\\n\")
    z.writestr(n+\"/METADATA\",\"Metadata-Version: 2.1\\nName: agentbox-probe\\nVersion: 0.1\\n\")
    z.writestr(n+\"/WHEEL\",\"Wheel-Version: 1.0\\nGenerator: t\\nRoot-Is-Purelib: true\\nTag: py3-none-any\\n\")
    z.writestr(n+\"/RECORD\",\"\")
PY
    python -m pip install --user --no-index --disable-pip-version-check -q ./agentbox_probe-0.1-py3-none-any.whl
    cd / && python -c \"import agentbox_probe,sys; assert agentbox_probe.OK==42; print(agentbox_probe.__file__)\"'"

size=$(docker image inspect "$IMAGE" --format '{{.Size}}')
echo "image $IMAGE size: $((size / 1000000)) MB"
if [ "$fails" -gt 0 ]; then echo "RESULT: $fails FAIL"; exit 1; fi
echo "RESULT: all PASS"
