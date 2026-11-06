#!/usr/bin/env bash
# ../.env.local 의 값으로 예제를 띄운다 (http://localhost:4102)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi
export CLIENT_ID="${EXPRESS_CLIENT_ID:-sample-express}"
export CLIENT_SECRET="${EXPRESS_CLIENT_SECRET:-change-me}"
export APP_BASE_URL="${APP_BASE_URL:-http://localhost:4102}"
export PORT="${PORT:-4102}"
[ -d node_modules ] || npm ci
exec node app.js
