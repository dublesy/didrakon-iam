# 한 이미지에 Apache httpd + mod_auth_openidc(앞단)와 C++ 앱(뒤, 127.0.0.1:9000)을 함께 둔다
FROM debian:trixie-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
      g++ libcpp-httplib-dev nlohmann-json3-dev libssl-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY app/main.cpp .
RUN g++ -std=c++17 -O2 -Wall -o /iam-sample-app main.cpp -lcpp-httplib -lssl -lcrypto -lpthread

FROM debian:trixie-slim
# socat: 컨테이너 안의 localhost:8080 을 호스트의 IAM 으로 넘긴다 (토큰 iss 가 http://localhost:8080 이어야 한다)
RUN apt-get update && apt-get install -y --no-install-recommends \
      apache2 libapache2-mod-auth-openidc libcpp-httplib0.18 openssl socat ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && a2enmod proxy proxy_http auth_openidc alias headers \
    && a2dissite 000-default \
    && sed -i 's/^Listen 80$//' /etc/apache2/ports.conf
COPY --from=build /iam-sample-app /usr/local/bin/iam-sample-app
COPY iam-proxy.conf /etc/apache2/sites-enabled/iam-proxy.conf
COPY docker-entrypoint.sh /usr/local/bin/
ENV APP_BASE_URL=http://localhost:4110
EXPOSE 4110
ENTRYPOINT ["docker-entrypoint.sh"]
