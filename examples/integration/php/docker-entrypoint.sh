#!/bin/sh
set -e
socat TCP-LISTEN:8080,fork,reuseaddr,bind=127.0.0.1 TCP:host.docker.internal:8080 &
exec php -S "0.0.0.0:${APP_PORT}" public/index.php
