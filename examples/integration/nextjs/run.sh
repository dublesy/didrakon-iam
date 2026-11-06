#!/usr/bin/env bash
# ../.env.local 의 값으로 예제를 빌드해 띄운다 (http://localhost:4103). 개발 모드는 ./run.sh dev
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi
export CLIENT_ID="${NEXTJS_CLIENT_ID:-sample-nextjs}"
export CLIENT_SECRET="${NEXTJS_CLIENT_SECRET:-change-me}"
export APP_BASE_URL="${APP_BASE_URL:-http://localhost:4103}"
[ -d node_modules ] || npm ci
if [ "${1:-}" = "dev" ]; then exec npx next dev -p 4103; fi
npx next build
exec npx next start -p 4103
