#!/usr/bin/env bash
# Build agentbox/agent:<hash> and tag agentbox/agent:latest.
# <hash> = first 12 hex of sha256 over the build inputs (versions.env,
# Dockerfile, and every file the Dockerfile copies), with their names.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
cd "$here"

inputs=(Dockerfile versions.env managed-mcp.json pi-mcp.json pi-wrapper with-secrets
        pi-mcp-adapter/package.json pi-mcp-adapter/package-lock.json pi-mcp-adapter/.npmrc)
for f in "${inputs[@]}"; do [ -f "$f" ] || { echo "missing input: $f" >&2; exit 1; }; done
hash=$(for f in "${inputs[@]}"; do printf '%s\0' "$f"; cat "$f"; printf '\0'; done \
       | shasum -a 256 | cut -c1-12)

build_args=()
while IFS= read -r line || [ -n "$line" ]; do
  case $line in ''|'#'*) continue ;; esac
  key=${line%%=*}
  case $key in *[!A-Za-z0-9_]*|'') echo "bad versions.env line: $line" >&2; exit 1 ;; esac
  build_args+=(--build-arg "$line")
done < versions.env

tag="agentbox/agent:${hash}"
echo "building ${tag}"
docker build --platform linux/amd64 "${build_args[@]}" -t "$tag" -t agentbox/agent:latest "$here"
echo "built ${tag} (also agentbox/agent:latest)"
