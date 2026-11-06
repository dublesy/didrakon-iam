#!/usr/bin/env bash
# 예제 실행: ../.env.local 을 읽어 http://localhost:4101 로 띄운다
set -euo pipefail
cd "$(dirname "$0")"
if [ -f ../.env.local ]; then set -a; . ../.env.local; set +a; fi
export IAM_CLIENT_ID="${SPRING_BOOT_CLIENT_ID:-sample-spring-boot}"
export IAM_CLIENT_SECRET="${SPRING_BOOT_CLIENT_SECRET:-dummy-secret}"
exec ./gradlew --quiet bootRun
