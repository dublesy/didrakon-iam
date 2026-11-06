# 코드를 고칠 수 없는 시스템 — 인증 프록시 빠른 시작

C++ 처럼 OIDC 라이브러리를 넣기 어렵거나 소스를 고칠 수 없는 시스템은 앞에 **인증 프록시**를 두고 붙인다. 로그인·토큰 검증·세션·back-channel 로그아웃은 프록시가 하고, 시스템은 프록시가 넘겨준 헤더(사용자 ID, 사번, 역할)만 읽는다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있다.

예제: [`examples/integration/proxy/`](../../examples/integration/proxy/) — Apache httpd + [mod_auth_openidc](https://github.com/OpenIDC/mod_auth_openidc) 설정 [`iam-proxy.conf`](../../examples/integration/proxy/iam-proxy.conf), 뒤의 C++ 앱 [`app/main.cpp`](../../examples/integration/proxy/app/main.cpp)(OIDC 코드 없음). 둘을 이미지 하나에 담았다.

```
브라우저 ──▶ Apache + mod_auth_openidc (:4110) ──OIDC_CLAIM_* 헤더──▶ C++ 앱 (127.0.0.1:9000)
                 ▲ 로그인·토큰·세션                                    /login, /me, /webhooks/iam
IAM ─────────────┘ back-channel 로그아웃 (/callback?logout=backchannel)
IAM 웹훅 ──▶ Apache (로그인 없이 통과) ──▶ C++ 앱이 HMAC 검증
```

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Docker | 이미지 `debian:trixie-slim` (Debian 13) |
| Apache httpd | 2.4.69 (Debian `apache2`) |
| mod_auth_openidc | 2.4.17 (Debian `libapache2-mod-auth-openidc`) |
| C++ 앱 | g++ 14, C++17, cpp-httplib 0.18.7, nlohmann/json 3.11.3, OpenSSL 3.5 (모두 Debian 패키지) |

배포판 패키지가 오래됐으면 [OpenIDC 릴리스](https://github.com/OpenIDC/mod_auth_openidc/releases)의 패키지를 쓴다 (`OIDCPKCEMethod`·back-channel 로그아웃이 있는 버전).

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-proxy` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4110/callback` |
| 로그아웃 알림 주소 | **`http://localhost:4110/callback?logout=backchannel`** (mod_auth_openidc 가 받는 주소) |
| 로그아웃 뒤 돌아갈 주소 | `http://localhost:4110/me` (`/logout` 이 `post_logout_redirect_uri` 로 보낸다) |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 (프록시가 씀) | `sample-proxy`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 (C++ 앱이 씀) | 없음 (없으면 모든 웹훅 `401`) |
| `APP_BASE_URL` | 리다이렉트 URI 를 만들 주소 | `http://localhost:4110` |
| `OIDC_CRYPTO_PASSPHRASE` | 프록시 쿠키 암호화 키 | 컨테이너가 뜰 때마다 `openssl rand` 로 만든다 |

[`run.sh`](../../examples/integration/proxy/run.sh) 가 `.env.local` 의 `PROXY_CLIENT_ID`·`PROXY_CLIENT_SECRET` 을 넘기고 이미지를 만들어 띄운다. [`docker-entrypoint.sh`](../../examples/integration/proxy/docker-entrypoint.sh) 가 socat 으로 컨테이너의 8080 을 호스트 IAM 으로 넘기고(토큰 `iss` 를 맞추려고), C++ 앱과 Apache 를 띄운다.

## 4. 핵심 설정·코드

**계약 주소와 프록시의 대응**

| 계약 | 이 예제 |
|---|---|
| `GET /login` | 보호한 주소. 로그인하지 않았으면 프록시가 IAM 으로 보내고, 로그인 뒤 앱의 `/login` 이 `/me` 로 보낸다 |
| `GET /callback` | mod_auth_openidc 의 `OIDCRedirectURI`. state·nonce·PKCE·code 교환·ID 토큰 검증을 프록시가 한다 |
| `GET /me` | 앱이 헤더를 읽어 JSON. 로그인하지 않았으면 프록시가 IAM 으로 보내지 않고 `401` JSON |
| `GET /logout` | `/callback?logout=…` 로 넘겨 프록시 세션을 지우고 IAM `/connect/logout?id_token_hint=…` 로 |
| `POST /backchannel-logout` | **`POST /callback?logout=backchannel`** (프록시가 검증하고 세션 캐시에서 지움) |
| `POST /webhooks/iam` | 프록시는 로그인 없이 통과시키고, 앱이 HMAC 으로 검증 |

**IAM 연결** ([`iam-proxy.conf`](../../examples/integration/proxy/iam-proxy.conf))

```apache
OIDCProviderMetadataURL ${IAM_ISSUER}/.well-known/openid-configuration
OIDCClientID ${CLIENT_ID}
OIDCClientSecret ${CLIENT_SECRET}
OIDCProviderTokenEndpointAuth client_secret_basic
OIDCRedirectURI ${APP_BASE_URL}/callback
OIDCScope "openid profile"
OIDCPKCEMethod S256                    # PKCE 는 켜야 쓴다
OIDCIDTokenSignedResponseAlg RS256     # HS256(client secret 서명) 토큰을 받지 않는다
OIDCCryptoPassphrase ${OIDC_CRYPTO_PASSPHRASE}
OIDCSessionType server-cache           # 세션은 서버 캐시, 쿠키에는 ID 만 → back-channel 로그아웃으로 지울 수 있다
OIDCPassClaimsAs headers none          # OIDC_CLAIM_sub, OIDC_CLAIM_emp_no, OIDC_CLAIM_roles=a,b ...
```

**경로별 보호**

```apache
<Location />                 # 기본은 로그인 필요
    AuthType openid-connect
    Require valid-user
</Location>
<Location /me>               # API 처럼 쓰는 주소: IAM 으로 보내지 않고 401 JSON
    OIDCUnAuthAction 401
    ErrorDocument 401 "{\"error\":\"unauthorized\"}"
    Header always set Content-Type "application/json; charset=utf-8" "expr=%{REQUEST_STATUS} == 401"
</Location>
<Location /webhooks/iam>     # 서버 간 호출: 로그인 없이, 앱이 HMAC 으로 확인
    AuthType None
    Require all granted
</Location>
```

**C++ 앱** — OIDC 코드 없이 헤더를 읽고 계정을 잇는다(`sub` → `emp_no` → JIT).

```cpp
std::string sub = req.get_header_value("OIDC_CLAIM_sub");
if (sub.empty()) return reply_json(res, 401, {{"error", "unauthorized"}});
LocalUser user = link_account(sub, req.get_header_value("OIDC_CLAIM_emp_no"), req.get_header_value("OIDC_CLAIM_name"));
// roles 는 쉼표로 이어 온다, sid 도 OIDC_CLAIM_sid 로 온다
```

**웹훅** — 받은 본문 그대로 OpenSSL HMAC 을 계산하고 `CRYPTO_memcmp` 로 상수 시간 비교한다.

```cpp
std::string expected = "sha256=" + hmac_sha256_hex(secret, timestamp + "." + req.body);
bool ok = signature.size() == expected.size() &&
          CRYPTO_memcmp(signature.data(), expected.data(), expected.size()) == 0;
```

그다음 시각(300초), `X-Didrakon-Delivery` 중복을 보고, `RETIRED` 면 로컬 계정을 끈다. 끈 계정은 프록시 세션이 남아 있어도 `/me` 가 `401` 이다.

## 5. 실행·검증

```bash
cd examples/integration/proxy
./run.sh                                   # docker build + run (포트 4110)

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4110                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4110 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **앱은 프록시를 거쳐서만 닿아야 한다.** 앱은 `OIDC_CLAIM_*` 헤더를 그대로 믿는다. 앱 포트가 밖에 열려 있으면 누구나 헤더를 꾸며 다른 사람으로 들어온다. 예제는 앱을 `127.0.0.1` 에만 연다. 서버가 나뉘면 방화벽·보안 그룹으로 프록시에서 오는 연결만 받고, 가능하면 mTLS 를 쓴다.
- mod_auth_openidc 는 보호한 경로로 들어온 같은 이름의 헤더를 지운다(`OIDCScrubRequestHeaders`, 기본 On). 로그인 없이 통과시키는 `/webhooks/iam` 에서는 지우지 않으므로, 앱은 그 경로에서 claim 헤더를 쓰지 않는다.
- **사용자 단위 back-channel 로그아웃은 프록시 세션을 끝내지 못한다.** IAM 은 사용 중지·잠금·퇴사 때 `sid` 없이 `sub` 만 담은 로그아웃 토큰을 보내는데, mod_auth_openidc 2.4.17 은 로그인 때 ID 토큰의 `sid` 로만 세션을 색인해 `sub` 로는 찾지 못한다(찾지 못해도 `200` 을 돌려준다). 그래서 앱이 **퇴사 웹훅으로 로컬 계정을 끄고 매 요청에서 확인**해야 한다. 잠금·사용 중지까지 막으려면 `DISABLED`·`LOCKED` 도 같은 식으로 처리하거나 `OIDCSessionInactivityTimeout` 을 짧게 둔다. IAM 로그아웃·관리자 세션 종료(`sid` 있음)는 프록시 세션이 바로 끝난다.
- mod_auth_openidc 2.4.17 은 로그아웃 토큰의 `typ: logout+jwt` 를 검사하지 않는다. 서명·`iss`·`aud`·`iat`·`events`·`nonce` 없음·`jti` 재사용은 검사한다.
- `OIDCCryptoPassphrase` 는 저장소·이미지에 두지 않는다. 예제는 시작할 때마다 만들어 재시작하면 로그인이 풀린다. 서버가 여러 대면 같은 값을 비밀 저장소에서 넣고 `OIDCCacheType redis` 로 세션 캐시를 공유한다.
- 역할 같은 배열 claim 은 쉼표로 이어 오므로(`OIDCClaimDelimiter`), 값에 쉼표가 있으면 구분자를 바꾼다. 이름 같은 한글 claim 은 UTF-8 그대로 온다(`OIDCPassClaimsAs headers none`). 앱이 헤더의 비 ASCII 를 못 다루면 `base64url` 로 바꾸고 앱에서 디코드한다.
- 운영은 https 로 두고 `OIDCRedirectURI` 도 https 로 등록한다.

### 다른 프록시를 쓴다면

| 프록시 | back-channel 로그아웃 | 비고 |
|---|---|---|
| **Apache + mod_auth_openidc** (이 예제) | 받음 (`?logout=backchannel`) | 위 `sub` 단위 한계 있음 |
| oauth2-proxy | **받지 못함** — v7.15.5 기준, 요청 이슈 [#1224](https://github.com/oauth2-proxy/oauth2-proxy/issues/1224) 가 열려 있다 | 세션 수명(`--cookie-expire`, Redis 세션)을 짧게 두고 퇴사 웹훅으로 보완해야 한다 |
| nginx + lua-resty-openidc (OpenResty) | **받지 못함** — 요청 이슈 [#572](https://github.com/zmartzone/lua-resty-openidc/issues/572) 가 열려 있다 | 직접 구현하려면 Lua 로 로그아웃 토큰을 검증하고 공유 세션 저장소에서 지워야 한다 |

back-channel 로그아웃은 연동 가이드의 필수 항목이므로, 이 중에서는 mod_auth_openidc 를 권한다.
