#!/usr/bin/env bash
# sample-rust 를 Docker 로 http://localhost:4106 에 띄운다. 값은 ../.env.local 에서 읽는다 (커밋하지 않음)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi

export IAM_ISSUER="${IAM_ISSUER:-http://localhost:8080}"
export CLIENT_ID="${RUST_CLIENT_ID:-sample-rust}"
export CLIENT_SECRET="${RUST_CLIENT_SECRET:-dummy-secret}"   # 등록 전에도 앱이 뜨도록 둔 임시값
export WEBHOOK_SECRET="${WEBHOOK_SECRET:?../.env.local 에 WEBHOOK_SECRET 이 필요합니다}"

docker build -t didrakon-sample-rust .
# 비밀값은 이름만 넘겨 명령줄·이미지에 남지 않게 한다
exec docker run --rm --name didrakon-sample-rust -p 4106:4106 \
  --add-host=host.docker.internal:host-gateway \
  -e IAM_ISSUER -e CLIENT_ID -e CLIENT_SECRET -e WEBHOOK_SECRET -e PORT=4106 \
  didrakon-sample-rust
