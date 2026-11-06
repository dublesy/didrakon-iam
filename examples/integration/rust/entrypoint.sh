#!/bin/sh
# 로컬 개발용: 컨테이너의 localhost:8080 → 호스트의 IAM. 운영에서는 https IAM 주소를 IAM_ISSUER 로 주고 이 줄을 뺀다
socat TCP-LISTEN:8080,fork,reuseaddr TCP:host.docker.internal:8080 &
exec /usr/local/bin/app
