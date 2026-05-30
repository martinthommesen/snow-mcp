#!/usr/bin/env bash
# LIVE RPC verification against the ServiceNow instance in .dev.vars (Node path).
set -euo pipefail
cd "$(dirname "$0")/.."
npx tsc -b >/dev/null
node_modules/.bin/esbuild scripts/live-rpc-verify.mjs --bundle --platform=node --format=esm --outfile=.live-rpc-verify.bundle.mjs >/dev/null
DEV_VARS_PATH="$(pwd)/.dev.vars" node .live-rpc-verify.bundle.mjs
rm -f .live-rpc-verify.bundle.mjs
