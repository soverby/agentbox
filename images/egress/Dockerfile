# agentbox egress proxy (PLAN §2.2). Squid 6.13 on Ubuntu 24.04.
# ubuntu/squid:latest multi-arch index digest, looked up 2026-09-23.
ARG SQUID_IMAGE=ubuntu/squid@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029
FROM ${SQUID_IMAGE}
# Config (squid.conf + *.allow) is bind-mounted read-only at /etc/squid/agentbox.
# Logs go to a bind-mounted host dir at /var/log/agentbox.
COPY entrypoint.sh /usr/local/bin/agentbox-egress
RUN chmod 0755 /usr/local/bin/agentbox-egress \
 && mkdir -p /etc/squid/agentbox /var/log/agentbox /run/squid \
 && chown proxy:proxy /run/squid /var/log/agentbox
# Non-root, no capabilities needed. Compose adds read_only + tmpfs /run/squid, /tmp.
USER proxy
EXPOSE 3128
ENTRYPOINT ["/usr/local/bin/agentbox-egress"]
