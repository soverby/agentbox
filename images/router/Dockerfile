# agentbox model router (PLAN §2.5): LiteLLM proxy, non-root image variant.
# ghcr.io/berriai/litellm-non_root:v1.102.1 (released 2026-09-23; stable line),
# multi-arch index digest looked up 2026-09-23. Post-dates the published
# proxy advisories (latest: GHSA-3cv6-jpf6-8222, request-body routing params
# SSRF, 2026-08-26, patched 1.96.2). Only this pinned image is used: the
# LiteLLM PyPI package was compromised in March 2026 (PLAN §6).
# Cosign-signed: see the v1.102.1 release notes for `cosign verify`.
ARG LITELLM_IMAGE=ghcr.io/berriai/litellm-non_root:v1.102.1@sha256:ce9eec5907c9828706183dc9b80962f932ad2e34171fc8c7f131e3deda439f36
FROM ${LITELLM_IMAGE}
USER root
COPY entrypoint.sh /usr/local/bin/agentbox-router
COPY agentbox_guard.py /opt/agentbox-router/agentbox_guard.py
# The image's files under /app and /var/lib/litellm belong to uid 65534, so
# the router runs as uid 10003 (no file of its own); the one world-writable
# file (/app/.venv/.lock) loses o+w. The guard is root-owned 0644.
RUN chmod 0755 /usr/local/bin/agentbox-router /opt/agentbox-router \
 && chmod 0644 /opt/agentbox-router/agentbox_guard.py \
 && chmod o-w /app/.venv/.lock \
 && (find / -xdev -perm /6000 -type f -exec chmod a-s {} + 2>/dev/null || true) \
 && test -z "$(find / -xdev -perm /6000 -type f 2>/dev/null)"
ENV PYTHONPATH=/opt/agentbox-router \
    HOME=/tmp
USER 10003:10003
EXPOSE 4000
ENTRYPOINT ["/usr/local/bin/agentbox-router"]
