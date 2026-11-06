#!/usr/bin/env bash
# Docker(ruby:3.3)로 빌드하고 띄운다: http://localhost:4109
set -euo pipefail
cd "$(dirname "$0")"

# ../.env.local 을 읽는다 (값을 셸 코드로 실행하지 않게 한 줄씩)
if [ -f ../.env.local ]; then
  while IFS='=' read -r key value; do
    case "$key" in ''|\#*) continue ;; esac
    export "$key=$value"
  done < ../.env.local
fi
export IAM_ISSUER="${IAM_ISSUER:-http://localhost:8080}"
export WEBHOOK_SECRET="${WEBHOOK_SECRET:-}"
export CLIENT_ID="${RUBY_CLIENT_ID:-sample-ruby}"
export CLIENT_SECRET="${RUBY_CLIENT_SECRET:-change-me}"   # 클라이언트를 등록하기 전에도 앱은 뜬다
export APP_URL="http://localhost:4109"

docker build -t didrakon-sample-ruby .
# -e NAME 만 쓰면 값이 명령줄(ps)에 드러나지 않는다
exec docker run --rm --name didrakon-sample-ruby -p 4109:4109 \
  --add-host=host.docker.internal:host-gateway \
  -e IAM_ISSUER -e WEBHOOK_SECRET -e CLIENT_ID -e CLIENT_SECRET -e APP_URL \
  didrakon-sample-ruby
