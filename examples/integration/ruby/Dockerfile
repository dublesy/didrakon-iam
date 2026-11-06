FROM ruby:3.3
# socat: 컨테이너 안의 localhost:8080 을 호스트의 IAM 으로 넘긴다 (토큰 iss 가 http://localhost:8080 이어야 한다)
RUN apt-get update && apt-get install -y --no-install-recommends socat && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY Gemfile Gemfile.lock ./
RUN bundle install --jobs 4
COPY app.rb ./
EXPOSE 4109
CMD ["sh", "-c", "socat TCP-LISTEN:8080,fork,reuseaddr TCP:host.docker.internal:8080 & exec bundle exec ruby app.rb"]
