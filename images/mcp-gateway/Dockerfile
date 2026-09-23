# agentbox mcp-gateway (PLAN §2.6). FastMCP 4.0.5 from a hash-locked
# requirements file (`uv pip compile --universal --generate-hashes`, see lock.sh).
# python:3.13-slim multi-arch index digest, looked up 2026-09-23 (same as ollama-gate).
ARG PYTHON_IMAGE=python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
# uv 0.12.18 (same version as the agent image), for `uvx` stdio servers.
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.12.18@sha256:3adc3706091ce7c2fe595e669628caedd6d951551b92b258b7e7dbe06d9440bc
FROM ${UV_IMAGE} AS uv

# ---------------------------------------------------------------- Node.js 24
# Same version + sha256 as images/agent/versions.env (a unit test checks that
# they match), for `npx` / `node` stdio servers. linux-x64 tarball: amd64 only.
FROM ${PYTHON_IMAGE} AS node
ARG NODE_VERSION=24.21.0
ARG NODE_SHA256=fd8e59d5a511510f6a298afb548f18c7d2b1be404d8b4a27d94fbe49f56cb2d6
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends curl ca-certificates xz-utils \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /out
RUN f="node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${f}" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" \
 && grep " ${f}\$" SHASUMS256.txt | sha256sum -c - \
 && echo "${NODE_SHA256}  ${f}" | sha256sum -c - \
 && mkdir node && tar -xJf "${f}" -C node --strip-components=1 \
      --exclude='*/share/doc' --exclude='*/share/man' --exclude='*/include' \
      --exclude='*/CHANGELOG.md' --exclude='*/README.md' \
 && rm -f "${f}" SHASUMS256.txt \
 && chown -R root:root /out && chmod -R go-w /out

# ---------------------------------------------------------------- final image
FROM ${PYTHON_IMAGE}
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
COPY requirements.lock /opt/mcp-gateway/requirements.lock
RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/pip install --no-cache-dir --disable-pip-version-check \
      --require-hashes --only-binary=:all: -r /opt/mcp-gateway/requirements.lock \
 && useradd --uid 10002 --no-create-home --shell /usr/sbin/nologin mcpgw \
 && mkdir -p /var/log/mcp && chown mcpgw /var/log/mcp \
 && mkdir -p /var/lib/mcp-oauth && chown mcpgw:mcpgw /var/lib/mcp-oauth && chmod 0700 /var/lib/mcp-oauth
# Node.js into /usr/local (the tarball's uid 1001 was reset to root above).
COPY --from=node /out/node/ /usr/local/
COPY --from=uv /uv /uvx /usr/local/bin/
# /var/lib/mcp-oauth: mount point of the gateway-only OAuth volume (P6b); a new
# named volume copies this dir's owner and mode (mcpgw, 0700).
COPY entrypoint.sh gateway.py upstream_oauth.py /opt/mcp-gateway/
# Build-time ownership checks: nothing under /usr/local or /opt is owned by a
# non-root uid or writable by group/other; no setuid/setgid; no world-writable
# dirs (the gateway service is not read_only, see PLAN §2.6).
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && chmod 0755 /var/tmp /run/lock \
 && bad=$(find /usr/local /opt \( ! -uid 0 -o -perm /022 \) ! -type l -print | head -5) \
 && { [ -z "${bad}" ] || { echo "FATAL: non-root-owned or writable: ${bad}" >&2; exit 1; }; } \
 && [ "$(node --version)" = "v24.21.0" ] && npx --version >/dev/null
ENV PATH=/opt/venv/bin:/usr/local/bin:/usr/bin:/bin \
    PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 \
    HOME=/tmp UV_CACHE_DIR=/tmp/uv-cache UV_PYTHON_PREFERENCE=only-system \
    NPM_CONFIG_CACHE=/tmp/npm-cache NPM_CONFIG_UPDATE_NOTIFIER=false \
    FASTMCP_CHECK_FOR_UPDATES=off
USER mcpgw
EXPOSE 8080
ENTRYPOINT ["/opt/mcp-gateway/entrypoint.sh"]
