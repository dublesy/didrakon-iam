# Rust 빠른 시작

[axum](https://github.com/tokio-rs/axum) 에 [openidconnect](https://github.com/ramosbugs/openidconnect-rs) 로 IAM 에 붙인다. back-channel 로그아웃 토큰은 openidconnect 에 해당 타입이 없어 [jsonwebtoken](https://github.com/Keats/jsonwebtoken) 으로 IAM JWKS 를 써서 검증한다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고 여기서는 Rust 코드만 다룬다.

예제: [`examples/integration/rust/`](../../examples/integration/rust/) — [`src/main.rs`](../../examples/integration/rust/src/main.rs) 하나에 계약의 모든 주소가 있다.

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Rust | 1.99 (예제는 Docker `rust:1.99-slim-trixie` 로 빌드, 실행은 `debian:trixie-slim`) |
| `openidconnect` | 4.1.0 (`reqwest`·`rustls-tls` 기능. discovery, PKCE, nonce, ID 토큰 검증) |
| `axum` / `axum-extra` | 0.8.9 / 0.10.3 (`cookie` 기능) |
| `tokio` | 1.54.1 |
| `jsonwebtoken` | 9.3.1 (로그아웃 토큰 검증) |
| `hmac` / `sha2` / `hex` | 0.12.1 / 0.10.9 / 0.4.3 (웹훅 서명) |

버전은 [`Cargo.lock`](../../examples/integration/rust/Cargo.lock)에 고정했고 이미지 빌드는 `--locked` 로 한다. HTTP 클라이언트는 openidconnect 가 다시 내보내는 `openidconnect::reqwest`(0.12)를 그대로 쓴다.

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-rust` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4106/callback` |
| 로그아웃 알림 주소 | `http://localhost:4106/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 | `sample-rust`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | 없음 |
| `PORT`, `APP_BASE_URL` | 포트, 리다이렉트 URI 를 만들 앱 주소 | `4106`, `http://localhost:4106` |

[`run.sh`](../../examples/integration/rust/run.sh) 가 `examples/integration/.env.local` 의 `RUST_CLIENT_ID`·`RUST_CLIENT_SECRET` 을 `CLIENT_ID`·`CLIENT_SECRET` 으로 바꿔 이미지를 빌드하고 컨테이너를 띄운다 (`-p 4106:4106`). 비밀값은 `-e 이름` 으로만 넘겨 명령줄·이미지에 남기지 않는다.

**컨테이너 안의 IAM 주소**: 토큰의 `iss` 가 `http://localhost:8080` 이므로 컨테이너 안에서도 같은 주소로 IAM 을 불러야 한다. [`entrypoint.sh`](../../examples/integration/rust/entrypoint.sh) 가 `socat` 으로 컨테이너의 `localhost:8080` 을 `host.docker.internal:8080` 으로 넘긴다. 로컬 개발용이고 운영에서는 https IAM 주소를 그대로 쓴다.

## 4. 핵심 코드

**IAM claim 을 타입으로** — `emp_no`·`roles`·`sid` 는 표준 claim 이 아니므로 `AdditionalClaims` 로 선언하고, 그 타입을 쓰는 `Client` 별칭을 만든다. 로그아웃 주소(`end_session_endpoint`)도 같은 방식으로 discovery 에서 읽는다.

```rust
#[derive(Clone, Debug, Deserialize, Serialize)]
struct IamClaims {
    emp_no: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    sid: Option<String>,
}
impl AdditionalClaims for IamClaims {}
// IamTokenResponse = StandardTokenResponse<IdTokenFields<IamClaims, ...>, CoreTokenType>
// IamClient = Client<IamClaims, ..., IamTokenResponse, ..., EndpointSet, ..., EndpointMaybeSet, EndpointMaybeSet>
```

**discovery** — 리다이렉트를 따라가지 않는 HTTP 클라이언트로 discovery·JWKS 를 읽는다. 로컬의 `http://` issuer 도 그대로 받는다.

```rust
let http = reqwest::ClientBuilder::new().redirect(reqwest::redirect::Policy::none()).build()?;
let metadata = IamProviderMetadata::discover_async(IssuerUrl::new(issuer)?, &http).await?;
let client: IamClient = Client::from_provider_metadata(metadata, ClientId::new(id), Some(ClientSecret::new(secret)))
    .set_redirect_uri(RedirectUrl::new(format!("{base_url}/callback"))?);
```

**로그인** — `state`·`nonce`·PKCE verifier 를 서버 세션에 둔다.

```rust
let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
let (url, state, nonce) = client
    .authorize_url(AuthenticationFlow::<CoreResponseType>::AuthorizationCode, CsrfToken::new_random, Nonce::new_random)
    .add_scope(Scope::new("profile".into()))
    .set_pkce_challenge(challenge)
    .url();
```

**콜백** — `claims()` 가 서명(JWKS)·`iss`·`aud`·`exp`·`nonce` 를 한 번에 검증한다.

```rust
let token = client.exchange_code(AuthorizationCode::new(code))?
    .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
    .request_async(&http).await?;
let claims = token.id_token().ok_or(..)?
    .claims(&client.id_token_verifier(), &Nonce::new(pending.nonce))?;
let extra = claims.additional_claims();     // emp_no, roles, sid
```

계정 연결(`sub` → `emp_no` → JIT)은 [`link_account`](../../examples/integration/rust/src/main.rs), 로그인 뒤에는 세션 ID 를 새로 만든다(세션 고정 방지).

**back-channel 로그아웃** — `typ` 를 먼저 보고, 헤더의 `kid` 로 IAM JWKS 에서 키를 찾아 jsonwebtoken 으로 검증한다.

```rust
let header = jsonwebtoken::decode_header(token)?;
if header.typ.as_deref() != Some("logout+jwt") { return Err(..) }
let jwks: JwkSet = serde_json::from_slice(&http.get(&jwks_uri).send().await?.bytes().await?)?;
let key = DecodingKey::from_jwk(jwks.find(&kid).ok_or(..)?)?;
let mut v = Validation::new(Algorithm::RS256);
v.set_issuer(&[&issuer]);
v.set_audience(&[&client_id]);
v.set_required_spec_claims(&["exp", "iss", "aud"]);
let c = jsonwebtoken::decode::<LogoutClaims>(token, &key, &v)?.claims;
// LogoutClaims.iat 는 u64(없으면 역직렬화 실패), nonce 가 있으면 거부, events 에 backchannel-logout 이 있어야 함
```

`sid` 가 있으면 그 `sid` 를 가진 세션만, 없으면 `sub` 의 세션을 모두 지운다. 폼이 없거나 검증에 실패하면 `400` ([`backchannel_logout`](../../examples/integration/rust/src/main.rs)).

**웹훅** — 본문을 `Bytes` 로 받아 그대로 HMAC 을 계산하고, `verify_slice` 로 상수 시간 비교한다.

```rust
let mut mac = Hmac::<Sha256>::new_from_slice(secret)?;
mac.update(ts.as_bytes());
mac.update(b".");
mac.update(&body);
mac.verify_slice(&hex::decode(sig_hex)?).is_ok()
```

그다음 시각(300초), `X-Didrakon-Delivery` 중복을 보고, `user.status_changed` 가 `RETIRED` 면 로컬 계정을 끄고 그 사용자의 세션을 지운다 ([`webhook`](../../examples/integration/rust/src/main.rs)).

## 5. 실행·검증

```bash
cd examples/integration/rust
./run.sh                                   # docker build → docker run -p 4106:4106

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4106                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4106 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

첫 빌드는 의존성 컴파일로 몇 분 걸린다. Dockerfile 이 의존성 층을 따로 캐시하므로 `src/` 만 고치면 다시 빌드가 빠르다.

## 6. 주의할 점

- **운영 issuer 는 https 여야 한다.** openidconnect 는 `http://` issuer 를 막지 않으므로 로컬에서는 그대로 되지만, 운영에서 http 를 쓰면 토큰·code 가 평문으로 오간다. 앱 주소도 https 로 하고 세션 쿠키에 `.secure(true)` 를 준다.
- **`Client` 는 시작할 때 받은 JWKS 를 들고 있다.** IAM 이 서명 키를 바꾸면 ID 토큰 검증이 실패하므로, 운영에서는 주기적으로 discovery 를 다시 읽어 `Client` 를 바꾸거나 재시작한다. 예제의 로그아웃 토큰 검증은 매번 JWKS 를 읽는다(운영은 캐시하고 모르는 `kid` 일 때만 다시 읽는다).
- **`typ` 를 꼭 본다.** 로그아웃 토큰과 ID 토큰은 같은 키로 서명되므로, `typ` 를 보지 않으면 ID 토큰을 로그아웃 토큰처럼 보내 남의 세션을 끊을 수 있다.
- axum 의 `Form` 추출기는 실패하면 `422` 를 준다. 계약은 `400` 이므로 `Result<Form<_>, FormRejection>` 으로 받아 직접 `400` 을 돌려준다.
- 세션·사용자·처리한 전달 ID 를 메모리(`Mutex<HashMap>`)에 두므로 재시작하면 사라지고, 인스턴스가 여럿이면 back-channel 로그아웃이 한 인스턴스에만 닿는다. 운영에서는 세션을 Redis·DB 에, 처리한 전달 ID 는 `webhook_deliveries(delivery_id PRIMARY KEY, received_at)` 같은 테이블에 두고 오래된 행을 지운다.
- `SameSite=Lax` 여야 IAM 에서 돌아오는 `/callback` 에 세션 쿠키가 붙는다.
