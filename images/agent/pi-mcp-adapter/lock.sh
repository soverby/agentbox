#!/usr/bin/env bash
# Regenerate package-lock.json with the image's own node/npm (needs network).
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
docker run --rm --user 0 --network bridge \
  -e HTTPS_PROXY= -e HTTP_PROXY= -e https_proxy= -e http_proxy= -e NPM_CONFIG_PREFIX= \
  -v "$here:/w" -w /w "${IMAGE:-agentbox/agent:latest}" \
  npm install --package-lock-only
