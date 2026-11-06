#!/usr/bin/env bash
# 로컬 Python(3.12 이상)으로 띄운다: http://localhost:4104
set -euo pipefail
cd "$(dirname "$0")"

# ../.env.local 을 읽는다 (값을 셸 코드로 실행하지 않게 한 줄씩)
if [ -f ../.env.local ]; then
  while IFS='=' read -r key value; do
    case "$key" in ''|\#*) continue ;; esac
    export "$key=$value"
  done < ../.env.local
fi
export CLIENT_ID="${PYTHON_CLIENT_ID:-sample-python}"
export CLIENT_SECRET="${PYTHON_CLIENT_SECRET:-change-me}"   # 클라이언트를 등록하기 전에도 앱은 뜬다
export APP_URL="http://localhost:4104"

PYTHON="${PYTHON:-python3}"
[ -d .venv ] || "$PYTHON" -m venv .venv
.venv/bin/pip install -q --disable-pip-version-check -r requirements.txt
exec .venv/bin/uvicorn app:app --host 127.0.0.1 --port 4104
