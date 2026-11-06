#!/bin/sh
set -e
socat TCP-LISTEN:8080,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:8080 &
# 앱은 루프백에만 연다 (프록시를 거쳐서만 닿는다)
iam-sample-app &
# mod_auth_openidc 의 쿠키 암호화 키. 저장소·이미지에 두지 않고 시작할 때마다 만든다
OIDC_CRYPTO_PASSPHRASE="$(openssl rand -hex 32)"
export OIDC_CRYPTO_PASSPHRASE
. /etc/apache2/envvars
mkdir -p "$APACHE_RUN_DIR" "$APACHE_LOCK_DIR" "$APACHE_LOG_DIR"
exec apache2 -DFOREGROUND
