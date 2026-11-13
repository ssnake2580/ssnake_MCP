#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v node >/dev/null; then
  RQ4_BUNDLED_NODE="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin"
  export PATH="$RQ4_BUNDLED_NODE:$PATH"
fi
command -v node >/dev/null || { echo 'Install Node.js >=22.22.0 or add it to PATH.' >&2; exit 1; }
test -f .local/config.json || { echo 'Copy config.example.json to .local/config.json and fill in your settings.' >&2; exit 1; }
export PROMPTFOO_CONFIG_DIR="$PWD/.local/promptfoo"
export PROMPTFOO_DISABLE_TELEMETRY=1
export PROMPTFOO_DISABLE_UPDATE=1
export PROMPTFOO_CACHE_ENABLED=false
mkdir -p artifacts
RQ4_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
node node_modules/promptfoo/dist/src/entrypoint.js eval \
  -c promptfooconfig.pilot.yaml --no-cache --no-share --no-table --max-concurrency 1 \
  -o "artifacts/promptfoo-${RQ4_RUN_ID}.json" "$@"
