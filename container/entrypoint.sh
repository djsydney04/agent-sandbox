#!/bin/sh
set -eu
mkdir -p /root/.codex
cp /etc/codex-sandbox/config.toml /root/.codex/config.toml
exec "$@"
