#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
if ! command -v node >/dev/null; then
  export PATH="$HOME/.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin:$PATH"
fi
export PROMPTFOO_CONFIG_DIR="$PWD/.local/promptfoo"
export PROMPTFOO_DISABLE_TELEMETRY=1
export PROMPTFOO_DISABLE_UPDATE=1
export PROMPTFOO_CACHE_ENABLED=false
mkdir -p artifacts
RQ4_RUN_ID="$(date -u +%Y%m%dT%H%M%SZ)-$$"
node node_modules/promptfoo/dist/src/entrypoint.js eval \
  -c promptfooconfig.study.json --no-cache --no-share --no-table --max-concurrency 1 \
  -o "artifacts/study-promptfoo-${RQ4_RUN_ID}.json" "$@"
