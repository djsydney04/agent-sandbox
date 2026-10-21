FROM node:22.23.4-bookworm-slim@sha256:de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d AS base
ARG CODEX_VERSION=0.164.0-alpha.9
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git python3 python3-venv iproute2 iptables dnsutils jq \
    && rm -rf /var/lib/apt/lists/* \
    && npm install --global "@openai/codex@${CODEX_VERSION}" \
    && mkdir -p /root/.codex /workspace \
    && dpkg --compare-versions \
        "$(dpkg-query --show --showformat='${Version}' ca-certificates)" ge '20250419~deb12u2'
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
