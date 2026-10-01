#!/bin/sh
set -eu
SANDBOX_ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
exec "$SANDBOX_ROOT/sandbox" docker -- "$@"
