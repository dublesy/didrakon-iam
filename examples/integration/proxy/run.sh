#!/usr/bin/env bash
# sample-proxy(Apache + mod_auth_openidc 앞단 + C++ 앱)를 Docker 로 http://localhost:4110 에 띄운다.
# 값은 ../.env.local 에서 읽는다 (커밋하지 않음)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi

export IAM_ISSUER="${IAM_ISSUER:-http://localhost:8080}"
export CLIENT_ID="${PROXY_CLIENT_ID:-sample-proxy}"
export CLIENT_SECRET="${PROXY_CLIENT_SECRET:-dummy-secret}"   # 등록 전에도 뜨도록 둔 임시값
export WEBHOOK_SECRET="${WEBHOOK_SECRET:?../.env.local 에 WEBHOOK_SECRET 이 필요합니다}"

docker build -t didrakon-sample-proxy .
# 비밀값은 -e 이름만 넘겨 명령줄·이미지에 남기지 않는다. 앱 포트(9000)는 열지 않는다
exec docker run --rm --name didrakon-sample-proxy -p 4110:4110 \
  --add-host=host.docker.internal:host-gateway \
  -e IAM_ISSUER -e CLIENT_ID -e CLIENT_SECRET -e WEBHOOK_SECRET \
  didrakon-sample-proxy
