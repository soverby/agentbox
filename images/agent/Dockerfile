# syntax=docker/dockerfile:1
# check=skip=SecretsUsedInArgOrEnv
# (the flagged ARGs are public key fingerprints, not secrets)
# agentbox agent image (docs/PLAN.md §2.1). Build with build.sh; every ARG
# value comes from versions.env.
ARG UBUNTU_IMAGE=must-be-set-by-build.sh

# ---------------------------------------------------------------- fetch stage
# Downloads and verifies third-party artifacts. Nothing from this stage
# reaches the final image except the files copied explicitly below.
FROM ${UBUNTU_IMAGE} AS fetch
ARG CLAUDE_KEY_FPR
ARG GH_KEY_FPRS
ARG NODE_VERSION
ARG NODE_SHA256
ARG OLLAMA_VERSION
ARG OLLAMA_SHA256
ARG UV_VERSION
ARG UV_SHA256
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl gnupg xz-utils zstd \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /out

# Repository signing keys: fail on any fingerprint that is not published.
RUN curl -fsSL https://downloads.claude.ai/keys/claude-code.asc -o claude-code.asc \
 && got=$(gpg --show-keys --with-colons claude-code.asc | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}') \
 && echo "claude-code primary key fingerprint: ${got}" \
 && [ "${got}" = "${CLAUDE_KEY_FPR}" ] \
 || { echo "FATAL: claude-code signing key fingerprint mismatch" >&2; exit 1; }
RUN curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg -o githubcli-archive-keyring.gpg \
 && got=$(gpg --show-keys --with-colons githubcli-archive-keyring.gpg | awk -F: '$1=="pub"{p=1;next} $1=="fpr"&&p{print $10;p=0}') \
 && echo "gh keyring primary key fingerprints: ${got}" \
 && for f in ${got}; do \
      case " ${GH_KEY_FPRS} " in *" ${f} "*) ;; \
        *) echo "FATAL: unexpected gh key fingerprint ${f}" >&2; exit 1;; esac; \
    done \
 && [ -n "${got}" ]

# Node.js: pinned sha256, cross-checked against the published SHASUMS256.txt.
RUN f="node-v${NODE_VERSION}-linux-x64.tar.xz" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/${f}" \
 && curl -fsSLO "https://nodejs.org/dist/v${NODE_VERSION}/SHASUMS256.txt" \
 && grep " ${f}\$" SHASUMS256.txt | sha256sum -c - \
 && echo "${NODE_SHA256}  ${f}" | sha256sum -c - \
 && mkdir node && tar -xJf "${f}" -C node --strip-components=1 \
      --exclude='*/share/doc' --exclude='*/share/man' --exclude='*/include' \
      --exclude='*/CHANGELOG.md' --exclude='*/README.md' \
 && rm -f "${f}" SHASUMS256.txt

# Ollama: client binary only. The archive holds ~1.3 GB of GPU libraries;
# extract only bin/ollama.
RUN f=ollama-linux-amd64.tar.zst \
 && curl -fsSL -o "${f}" "https://github.com/ollama/ollama/releases/download/v${OLLAMA_VERSION}/${f}" \
 && echo "${OLLAMA_SHA256}  ${f}" | sha256sum -c - \
 && mkdir ollama && tar --zstd -xf "${f}" -C ollama bin/ollama \
 && rm -f "${f}" && ls -la ollama/bin

# uv (static binaries).
RUN f=uv-x86_64-unknown-linux-gnu.tar.gz \
 && curl -fsSL -o "${f}" "https://github.com/astral-sh/uv/releases/download/${UV_VERSION}/${f}" \
 && echo "${UV_SHA256}  ${f}" | sha256sum -c - \
 && mkdir uv && tar -xzf "${f}" -C uv --strip-components=1 \
 && rm -f "${f}"

# Tarballs keep their build uid (node: 1001); COPY --from keeps it too.
RUN chown -R root:root /out && chmod -R go-w /out

# ---------------------------------------------------------------- final image
FROM ${UBUNTU_IMAGE}
ARG CLAUDE_CODE_VERSION
ARG GH_VERSION
ARG CODEX_VERSION
ARG PI_VERSION
ARG PI_MCP_ADAPTER_VERSION
ARG PYTHON_VERSION
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]

# Remove the stock uid-1000 user; create agent (uid/gid 1000). No sudo.
RUN userdel -r ubuntu \
 && groupadd --gid 1000 agent \
 && useradd --uid 1000 --gid 1000 --create-home --home-dir /home/agent \
      --shell /bin/bash agent

COPY --from=fetch /out/claude-code.asc /etc/apt/keyrings/claude-code.asc
COPY --from=fetch /out/githubcli-archive-keyring.gpg /etc/apt/keyrings/githubcli-archive-keyring.gpg
# ca-certificates first: apt needs it to reach the two https repositories.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends ca-certificates \
 && chmod 0644 /etc/apt/keyrings/* \
 && echo "deb [signed-by=/etc/apt/keyrings/claude-code.asc] https://downloads.claude.ai/claude-code/apt/stable stable main" \
      > /etc/apt/sources.list.d/claude-code.list \
 && echo "deb [arch=amd64 signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
      > /etc/apt/sources.list.d/github-cli.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      ca-certificates curl git jq ripgrep unzip less build-essential make \
      "claude-code=${CLAUDE_CODE_VERSION}" "gh=${GH_VERSION}" \
 && if dpkg -s sudo >/dev/null 2>&1; then apt-get purge -y sudo; fi \
 && rm -rf /var/lib/apt/lists/*

# Node.js 24 into /usr/local (root-owned).
COPY --from=fetch /out/node/ /usr/local/
COPY --from=fetch /out/ollama/bin/ollama /usr/local/bin/ollama
COPY --from=fetch /out/uv/uv /out/uv/uvx /usr/local/bin/

# Codex, Pi and pi-mcp-adapter as root into /usr/local/lib/node_modules.
# --ignore-scripts: none of the three needs an install script (test.sh runs
# each). --legacy-peer-deps: Pi supplies pi-ai/pi-tui/typebox to extensions,
# so the adapter must not pull its own copies.
# Pi's npm-shrinkwrap makes npm install esbuild for every platform; keep
# only linux-x64 (~270 MB saved). npm as root keeps tarball file owners
# (uid 1000 = agent would own them), so chown in this same layer (a
# later chown would copy the whole tree into a new layer).
RUN npm install -g --ignore-scripts --no-fund --no-audit --legacy-peer-deps \
      "@openai/codex@${CODEX_VERSION}" \
      "@earendil-works/pi-coding-agent@${PI_VERSION}" \
 && rm /usr/local/bin/pi \
 && find /usr/local/lib/node_modules -type d -path '*/node_modules/@esbuild/*' -prune \
      ! -name linux-x64 -exec rm -rf {} + \
 && tui=/usr/local/lib/node_modules/@earendil-works/pi-coding-agent/node_modules/@earendil-works/pi-tui/native \
 && rm -rf "${tui}/darwin" "${tui}/win32" "${tui}/linux/prebuilds/linux-arm64" \
 && npm cache clean --force && rm -rf /root/.npm \
 && chown -R root:root /usr/local/lib/node_modules \
 && chmod -R go-w /usr/local/lib/node_modules

# pi-mcp-adapter: exact tree from the committed package-lock.json (npm ci),
# in its own root-owned prefix. .npmrc sets legacy-peer-deps (Pi supplies
# pi-ai/pi-tui/typebox to extensions) and ignore-scripts.
COPY pi-mcp-adapter/package.json pi-mcp-adapter/package-lock.json pi-mcp-adapter/.npmrc \
     /usr/local/lib/agentbox/pi-mcp-adapter/
RUN cd /usr/local/lib/agentbox/pi-mcp-adapter \
 && [ "$(jq -r '.dependencies["pi-mcp-adapter"]' package.json)" = "${PI_MCP_ADAPTER_VERSION}" ] \
 && npm ci --ignore-scripts \
 && [ "$(jq -r .version node_modules/pi-mcp-adapter/package.json)" = "${PI_MCP_ADAPTER_VERSION}" ] \
 && rm -rf node_modules/recheck-jar \
 && mkdir -p /usr/local/share/agentbox \
 && { echo "# npm ls --all -g (codex, pi)"; npm ls --all -g || true; \
      echo; echo "# npm ls --all (pi-mcp-adapter, /usr/local/lib/agentbox/pi-mcp-adapter)"; \
      npm ls --all || true; } > /usr/local/share/agentbox/sbom-npm.txt \
 && grep -q '@openai/codex@' /usr/local/share/agentbox/sbom-npm.txt \
 && grep -q '@earendil-works/pi-coding-agent@' /usr/local/share/agentbox/sbom-npm.txt \
 && grep -q 'pi-mcp-adapter@' /usr/local/share/agentbox/sbom-npm.txt \
 && npm cache clean --force && rm -rf /root/.npm \
 && echo "non-root-owned files from npm tarballs: $(find /usr/local/lib ! -user root | wc -l)" \
 && chown -R root:root /usr/local/lib/agentbox /usr/local/share/agentbox \
 && chmod -R go-w /usr/local/lib/agentbox /usr/local/share/agentbox \
 && chmod 0644 /usr/local/share/agentbox/sbom-npm.txt
# Pi has no system-wide extension directory (only ~/.pi/agent and project
# .pi/). The wrapper loads the root-owned adapter with the documented
# `--extension` flag, so it works with an empty /home/agent volume.
COPY pi-wrapper /usr/local/bin/pi
RUN chmod 0755 /usr/local/bin/pi

# CPython (latest final) via uv into a system location.
RUN UV_PYTHON_INSTALL_DIR=/opt/python UV_PYTHON_BIN_DIR=/opt/python/bin \
      uv python install --no-cache "${PYTHON_VERSION}" \
 && py=$(UV_PYTHON_INSTALL_DIR=/opt/python uv python find --no-project --system "${PYTHON_VERSION}" 2>/dev/null \
         || ls -d /opt/python/cpython-${PYTHON_VERSION}-linux-x86_64-gnu/bin/python${PYTHON_VERSION%.*}) \
 && echo "python: ${py}" \
 && ln -sf "${py}" /usr/local/bin/python3 \
 && ln -sf "${py}" /usr/local/bin/python \
 && rm -rf /root/.cache /opt/python/.lock /opt/python/.cache \
 && find /opt/python -name EXTERNALLY-MANAGED -delete \
 && [ "$(/usr/local/bin/python --version)" = "Python ${PYTHON_VERSION}" ]

# Claude Code managed MCP: only the agentbox gateway.
COPY managed-mcp.json /etc/claude-code/managed-mcp.json
COPY with-secrets /usr/local/bin/with-secrets
# COPY and RUN create root-owned files; only set modes (a recursive chown
# of /usr/local would duplicate ~1 GB into a new layer). test.sh doctor 16
# checks the result.
# No setuid/setgid binaries (doctor 16).
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} + \
 && chmod 0755 /etc/claude-code /usr/local/bin/with-secrets \
 && chmod 0644 /etc/claude-code/managed-mcp.json \
 && find /usr/local /opt/python /etc/claude-code -xdev \( ! -user root -o -perm -o+w \) \
      ! -type l -printf "%u %m %p\n" > /tmp/bad \
 && { [ ! -s /tmp/bad ] || { echo "FATAL: non-root or world-writable:"; head -20 /tmp/bad; exit 1; } >&2; } \
 && rm -f /tmp/bad

ENV DISABLE_AUTOUPDATER=1 \
    DISABLE_UPDATES=1 \
    CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
    ENABLE_CLAUDEAI_MCP_SERVERS=false \
    NPM_CONFIG_PREFIX=/home/agent/.npm-global \
    PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/home/agent/.npm-global/bin:/home/agent/.local/bin \
    OLLAMA_HOST=http://ollama-gate:11434 \
    HTTPS_PROXY=http://egress:3128 \
    HTTP_PROXY=http://egress:3128 \
    https_proxy=http://egress:3128 \
    http_proxy=http://egress:3128 \
    NO_PROXY=router,mcp-gateway,ollama-gate,localhost,127.0.0.1 \
    no_proxy=router,mcp-gateway,ollama-gate,localhost,127.0.0.1

USER agent
WORKDIR /home/agent
CMD ["sleep", "infinity"]
