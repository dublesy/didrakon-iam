# 의존성은 composer.lock 그대로 설치한다 (vendor/ 는 커밋하지 않음)
FROM composer:2.8.12 AS deps
WORKDIR /app
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --classmap-authoritative

FROM php:8.3.36-cli-trixie
# socat: 컨테이너 안의 localhost:8080 을 호스트의 IAM 으로 넘긴다 (토큰 iss 가 http://localhost:8080 이어야 한다)
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=deps /app/vendor ./vendor
COPY src ./src
COPY public ./public
COPY docker-entrypoint.sh /usr/local/bin/
# PHP_CLI_SERVER_WORKERS: 내장 서버가 요청을 여럿 동시에 받게 한다 (예제용. 운영은 php-fpm + nginx/Apache)
ENV DATA_DIR=/tmp PHP_CLI_SERVER_WORKERS=4 APP_PORT=4107
EXPOSE 4107
ENTRYPOINT ["docker-entrypoint.sh"]
