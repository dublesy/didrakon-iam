# 빌드: Rust 공식 이미지 → 실행: debian slim (같은 trixie 기반이라 glibc 가 맞는다)
FROM rust:1.99-slim-trixie AS build
WORKDIR /app
COPY Cargo.toml Cargo.lock ./
# 의존성만 먼저 빌드해 캐시한다
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release --locked && rm -rf src
COPY src ./src
RUN touch src/main.rs && cargo build --release --locked

FROM debian:trixie-slim
# socat: 컨테이너 안의 localhost:8080 을 호스트 IAM 으로 넘긴다 (토큰 iss 가 http://localhost:8080 이므로)
RUN apt-get update && apt-get install -y --no-install-recommends socat ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /app/target/release/didrakon-sample-rust /usr/local/bin/app
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
EXPOSE 4106
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
