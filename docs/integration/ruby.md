# Ruby 빠른 시작 (Sinatra)

Sinatra 에 [openid_connect](https://github.com/nov/openid_connect) gem 으로 로그인을, [jwt](https://github.com/jwt/ruby-jwt) gem 으로 back-channel 로그아웃 토큰 검증을 붙인다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고 여기서는 Ruby 코드만 다룬다.

예제: [`examples/integration/ruby/`](../../examples/integration/ruby/) — 파일 하나([`app.rb`](../../examples/integration/ruby/app.rb))에 계약의 모든 주소가 있다. 사용자·세션·처리한 웹훅 전달은 메모리에 둔다.

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Ruby | 3.3 (Docker `ruby:3.3` 이미지. 로컬 Ruby 가 낮아도 된다) |
| `sinatra` | 4.2.1 (+ `rackup` 2.3.1, `puma` 8.0.2) |
| `openid_connect` | 2.5.0 (discovery, 인가 URL, code 교환, ID 토큰 검증. `rack-oauth2` 2.3.0·`json-jwt` 1.17.2 를 가져옴) |
| `jwt` | 3.3.0 (로그아웃 토큰 검증, JWKS) |

버전은 [`Gemfile`](../../examples/integration/ruby/Gemfile)·`Gemfile.lock` 에 고정했다.

**왜 `openid_connect` 인가.** `omniauth_openid_connect` 는 Rack 미들웨어가 `/auth/:provider/callback` 까지 처리해 단계가 코드에 드러나지 않고, OmniAuth 2 의 CSRF 설정(`POST /auth/...`)도 따로 필요하다. Sinatra 처럼 라우트를 직접 쓰는 앱에서는 `openid_connect` 로 인가 URL → code 교환 → ID 토큰 검증을 한 줄씩 쓰는 편이 읽기 쉽다. Rails 는 [아래](#rails-라면)처럼 OmniAuth 가 관례다.

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-ruby` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4109/callback` |
| 로그아웃 알림 주소 | `http://localhost:4109/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 | `sample-ruby`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | 없음 (없으면 웹훅을 모두 `401`) |
| `APP_URL` | 리다이렉트 URI 를 만들 앱 주소 | `http://localhost:4109` |

[`run.sh`](../../examples/integration/ruby/run.sh) 가 `examples/integration/.env.local` 의 `RUBY_CLIENT_ID`·`RUBY_CLIENT_SECRET` 을 `CLIENT_ID`·`CLIENT_SECRET` 으로 넘기고, 이미지를 빌드해 컨테이너로 띄운다. 값은 `docker run -e 이름` 으로만 넘겨 명령줄에 드러나지 않게 한다.

컨테이너 안에서도 IAM 이 `http://localhost:8080` 이어야 토큰의 `iss` 와 맞는다. [`Dockerfile`](../../examples/integration/ruby/Dockerfile) 이 `socat` 으로 컨테이너의 `localhost:8080` 을 호스트(`host.docker.internal:8080`)로 넘긴다.

## 4. 핵심 코드

**discovery 와 클라이언트** — issuer 하나로 모든 주소를 얻는다. discovery 는 기본으로 https 만 쓰므로 로컬 IAM 에서만 http 를 허용한다.

```ruby
SWD.url_builder = URI::HTTP if ISSUER.start_with?("http://")

def self.provider
  @provider ||= OpenIDConnect::Discovery::Provider::Config.discover!(ISSUER)
end

def self.client
  OpenIDConnect::Client.new(
    identifier: CLIENT_ID, secret: CLIENT_SECRET, redirect_uri: "#{APP_URL}/callback",
    authorization_endpoint: provider.authorization_endpoint,
    token_endpoint: provider.token_endpoint, userinfo_endpoint: provider.userinfo_endpoint
  )
end
```

**로그인** — 클라이언트 쪽 PKCE 도우미는 없으므로 `code_challenge` 를 직접 만든다. `state`·`nonce`·`code_verifier` 는 서버 세션에 둔다.

```ruby
code_verifier = SecureRandom.urlsafe_base64(48)
code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)
start_session("state" => state, "nonce" => nonce, "code_verifier" => code_verifier)
redirect IAM.client.authorization_uri(
  scope: %w[openid profile], state: state, nonce: nonce,
  code_challenge: code_challenge, code_challenge_method: "S256"
), 302
```

**콜백** — `state` 를 상수 시간 비교한 뒤 code 를 바꾸고, `decode` 가 JWKS 서명(`kid`)을, `verify!` 가 `iss`·`aud`·`exp`·`nonce` 를 본다.

```ruby
client.authorization_code = params["code"]
token = client.access_token!(:basic, code_verifier: pending["code_verifier"])   # client_secret_basic

id_token = OpenIDConnect::ResponseObject::IdToken.decode(token.id_token, IAM.provider)
id_token.verify!(issuer: ISSUER, client_id: CLIENT_ID, nonce: pending["nonce"])
claims = id_token.raw_attributes   # emp_no·roles 같은 IAM claim 까지 담긴 Hash
```

로그인한 세션은 새 세션 ID 로 만든다(세션 고정 방지). 계정 연결(`iam_subject_id` → `emp_no` → JIT)은 [`link_account`](../../examples/integration/ruby/app.rb).

**back-channel 로그아웃** — `jwt` gem 에 JWKS 로더를 주면 `kid` 로 키를 고르고, 모르는 `kid` 면 `invalidate: true` 로 다시 부른다. `iss`·`aud`·`iat` 검사는 **기본으로 꺼져 있으니** 켠다.

```ruby
claims, header = JWT.decode(
  params["logout_token"].to_s, nil, true,
  algorithms: ["RS256"], jwks: IAM.method(:jwks),
  iss: ISSUER, verify_iss: true,
  aud: CLIENT_ID, verify_aud: true,
  verify_iat: true, required_claims: %w[iss aud iat exp], leeway: 60
)
raise JWT::DecodeError, "typ" unless header["typ"] == "logout+jwt"
raise JWT::DecodeError, "events" unless (claims["events"] || {}).key?(BACKCHANNEL_EVENT)
raise JWT::DecodeError, "nonce" if claims.key?("nonce")
```

`sid` 가 있으면 그 `sid` 를 가진 세션만, 없으면 `sub` 의 세션을 모두 지운다. 서명·만료·`iss`·`aud` 실패는 모두 `JWT::DecodeError` 하위 클래스라 한곳에서 `400` 으로 돌려준다.

**웹훅** — `request.body.read` 로 받은 바이트 그대로 HMAC 을 계산하고 `Rack::Utils.secure_compare` 로 비교한다.

```ruby
request.body.rewind
raw = request.body.read
expected = "sha256=" + OpenSSL::HMAC.hexdigest("SHA256", WEBHOOK_SECRET, "#{timestamp}.#{raw}")
json_error 401, "bad_signature" unless Rack::Utils.secure_compare(expected, signature)
json_error 401, "stale_timestamp" unless (Time.now.to_i - timestamp.to_i).abs <= 300
```

그다음 `X-Didrakon-Delivery` 중복을 보고, `user.status_changed` 가 `RETIRED` 면 로컬 계정을 끄고 그 사용자의 세션을 지운다. 꺼진 계정은 다시 로그인해도 콜백에서 `403` 이다.

## 5. 실행·검증

```bash
cd examples/integration/ruby
./run.sh                                   # docker build + run (포트 4109). Ctrl-C 로 멈춘다

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4109                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4109 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **로그아웃 토큰의 `typ` 를 꼭 본다.** 로그아웃 토큰과 ID 토큰은 같은 키로 서명되므로, `typ` 를 보지 않으면 ID 토큰을 로그아웃 토큰처럼 보내 남의 세션을 끊을 수 있다.
- **`jwt` gem 은 `iss`·`aud`·`iat` 를 기본으로 검사하지 않는다.** `verify_iss`·`verify_aud`·`verify_iat` 와 `required_claims` 를 빼먹으면 다른 클라이언트용 토큰도 통과한다.
- `IdToken#verify!` 는 `exp` 에 여유를 두지 않는다. 서버 시각은 NTP 로 맞춘다.
- Sinatra 기본 세션(`enable :sessions`)은 쿠키 세션이라 back-channel 로그아웃으로 끝낼 수 없다. 예제는 세션 ID 만 쿠키에 두고 내용은 서버 메모리에 둔다. 운영에서는 Redis·DB 에 두고, 처리한 전달 ID 도 테이블에 둔다.
- puma 는 여러 스레드로 요청을 처리하므로 메모리 저장소는 `Mutex` 로 감싼다.
- 운영에서는 `APP_ENV=production` 으로 띄워 오류 화면에 스택 트레이스가 나가지 않게 하고, issuer 와 앱 주소를 https 로, 세션 쿠키에 `secure: true` 를 준다. `SameSite=Lax` 여야 IAM 에서 돌아오는 `/callback` 에 쿠키가 붙는다.
- Linux Docker 에는 `host.docker.internal` 이 없어 `run.sh` 가 `--add-host=host.docker.internal:host-gateway` 를 준다.

## Rails 라면

[omniauth_openid_connect](https://github.com/omniauth/omniauth_openid_connect) 를 쓴다 (안에서 같은 `openid_connect` gem 을 쓴다). 예제는 따로 두지 않는다.

- `config/initializers/omniauth.rb` 에 `provider :openid_connect, issuer:, discovery: true, scope: %i[openid profile], response_type: :code, pkce: true, client_auth_method: :basic, client_options: { identifier:, secret:, redirect_uri: }` 로 등록한다. nonce 는 기본으로 보낸다. `omniauth-rails_csrf_protection` 을 넣고 로그인 링크는 `POST /auth/openid_connect` 로 보낸다.
- 콜백 컨트롤러에서 `request.env["omniauth.auth"]` 의 `uid`(= `sub`)와 `extra.raw_info` 로 [계정 연결](README.md#5-계정-연결)한다. IAM 의 userinfo 응답(`raw_info`)에는 `sub` 와 `name` 같은 표준 claim 만 있고 `emp_no`·`roles` 는 없으므로, 이 값은 검증된 ID 토큰(`credentials.id_token`)을 위처럼 decode 해 읽는다.
- 기본 `CookieStore` 세션은 back-channel 로그아웃으로 끝낼 수 없다. `activerecord-session_store`·Redis 세션 저장소로 바꾸고, 로그인할 때 `sid`·`sub` 를 세션 행에 적어 둔다.
- back-channel 로그아웃은 OmniAuth 에 없다. 위 [back-channel 로그아웃](#4-핵심-코드) 코드를 컨트롤러로 만들고(`skip_forgery_protection`), 찾은 세션 행을 지운다.
