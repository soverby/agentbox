# agentbox ollama-gate (PLAN §2.5). Stdlib Python only.
# python:3.13-slim multi-arch index digest, looked up 2026-09-23.
ARG PYTHON_IMAGE=python:3.13-slim@sha256:8d9d0b8bcf6506481eae4907c18f5e3e7902e629f5f6d684f9e7c32e85e3ddf0
FROM ${PYTHON_IMAGE}
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin gate \
 && mkdir -p /var/log/agentbox && chown gate /var/log/agentbox
COPY gate.py /opt/gate/gate.py
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
USER gate
EXPOSE 11434
ENTRYPOINT ["python3", "/opt/gate/gate.py"]
