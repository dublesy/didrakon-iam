#!/usr/bin/env bash
# 예제 실행: ../.env.local 을 읽어 Docker 로 http://localhost:4108 에 띄운다
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi
export IAM_ISSUER="${IAM_ISSUER:-http://localhost:8080}"
export IAM_CLIENT_ID="${DOTNET_CLIENT_ID:-sample-dotnet}"
export IAM_CLIENT_SECRET="${DOTNET_CLIENT_SECRET:-dummy-secret}"
docker build -t didrakon-sample-dotnet .
# -e 이름만 주면 값은 현재 환경에서 넘어간다 (명령줄에 비밀값이 남지 않는다)
exec docker run --rm --name didrakon-sample-dotnet -p 4108:4108 \
  --add-host=host.docker.internal:host-gateway \
  -e IAM_ISSUER -e IAM_CLIENT_ID -e IAM_CLIENT_SECRET -e WEBHOOK_SECRET \
  didrakon-sample-dotnet
