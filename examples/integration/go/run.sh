#!/usr/bin/env bash
# sample-go 를 http://localhost:4105 에 띄운다. 값은 ../.env.local 에서 읽는다 (커밋하지 않음)
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi

export IAM_ISSUER="${IAM_ISSUER:-http://localhost:8080}"
export CLIENT_ID="${GO_CLIENT_ID:-sample-go}"
export CLIENT_SECRET="${GO_CLIENT_SECRET:-dummy-secret}"   # 등록 전에도 앱이 뜨도록 둔 임시값
export WEBHOOK_SECRET="${WEBHOOK_SECRET:?../.env.local 에 WEBHOOK_SECRET 이 필요합니다}"
export PORT=4105

exec go run .
