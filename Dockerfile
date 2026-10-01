FROM node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 AS base
ARG CODEX_VERSION=0.159.3
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv iproute2 iptables dnsutils jq \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global "@openai/codex@${CODEX_VERSION}" \
    && mkdir -p /root/.codex /workspace
COPY container/entrypoint.sh /usr/local/bin/sandbox-entrypoint
COPY tests/verify.py tests/check_codex.py /opt/sandbox/
RUN chmod +x /usr/local/bin/sandbox-entrypoint
WORKDIR /workspace
ENTRYPOINT ["sandbox-entrypoint"]
CMD ["bash"]

# Opt in through SANDBOX_IMAGE_TARGET=browser in .env.
FROM base AS browser
RUN apt-get update \
    && apt-get install -y --no-install-recommends chromium \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global @playwright/mcp@0.0.83
