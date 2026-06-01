#!/usr/bin/env bash
# LIVE RPC verification against the ServiceNow instance in .dev.vars (Node path).
set -euo pipefail
cd "$(dirname "$0")/.."
bundle="$(mktemp "${TMPDIR:-/tmp}/live-rpc-verify.XXXXXX.mjs")"
trap 'rm -f "$bundle"' EXIT
npx tsc -b >/dev/null
node_modules/.bin/esbuild scripts/live-rpc-verify.mjs --bundle --platform=node --format=esm --outfile="$bundle" >/dev/null
DEV_VARS_PATH="$(pwd)/.dev.vars" node "$bundle"
