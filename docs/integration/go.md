# Go 빠른 시작

Go 표준 `net/http` 에 [go-oidc](https://github.com/coreos/go-oidc) 와 `golang.org/x/oauth2` 로 IAM 에 붙인다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고 여기서는 Go 코드만 다룬다.

예제: [`examples/integration/go/`](../../examples/integration/go/) — 파일 하나([`main.go`](../../examples/integration/go/main.go))에 계약의 모든 주소가 있다.

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Go | 1.26 |
| `github.com/coreos/go-oidc/v3` | v3.21.0 (discovery, JWKS, ID 토큰 검증) |
| `golang.org/x/oauth2` | v0.37.0 (인가 URL, code 교환, PKCE) |
| `github.com/go-jose/go-jose/v4` | v4.1.4 (go-oidc 가 가져옴) |

버전은 [`go.mod`](../../examples/integration/go/go.mod)·`go.sum` 에 고정했다. 라우터는 Go 1.22+ 표준 `http.ServeMux` 의 `"GET /login"` 패턴을 쓴다.

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-go` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4105/callback` |
| 로그아웃 알림 주소 | `http://localhost:4105/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 | `sample-go`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | 없음 |
| `PORT`, `APP_BASE_URL` | 포트, 리다이렉트 URI 를 만들 앱 주소 | `4105`, `http://localhost:4105` |

[`run.sh`](../../examples/integration/go/run.sh) 가 `examples/integration/.env.local` 의 `GO_CLIENT_ID`·`GO_CLIENT_SECRET` 을 `CLIENT_ID`·`CLIENT_SECRET` 으로 넘긴다. 앱은 시작할 때 discovery 를 읽으므로 IAM 이 먼저 떠 있어야 한다.

## 4. 핵심 코드

**discovery 와 검증기** — issuer 하나로 모든 주소와 JWKS 를 얻는다. `Verifier` 는 서명(RS256)·`iss`·`aud`·`exp` 를 검사하고, 키가 바뀌면 JWKS 를 다시 읽는다.

```go
provider, err := oidc.NewProvider(ctx, issuer)
oauth := oauth2.Config{
    ClientID: clientID, ClientSecret: secret,
    Endpoint: provider.Endpoint(),            // 토큰 교환은 client_secret_basic
    RedirectURL: baseURL + "/callback",
    Scopes: []string{oidc.ScopeOpenID, "profile"},
}
idVerifier := provider.Verifier(&oidc.Config{ClientID: clientID})
```

**로그인** — `state`·`nonce`·PKCE verifier 를 서버 세션에 두고 보낸다.

```go
s := &Session{State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier()}
url := oauth.AuthCodeURL(s.State, oidc.Nonce(s.Nonce), oauth2.S256ChallengeOption(s.Verifier))
```

**콜백** — go-oidc 는 **nonce 를 검사하지 않는다**. 직접 비교한다.

```go
token, err := oauth.Exchange(ctx, code, oauth2.VerifierOption(pending.Verifier))
rawIDToken, _ := token.Extra("id_token").(string)
idToken, err := idVerifier.Verify(ctx, rawIDToken)
if err != nil || idToken.Nonce != pending.Nonce { /* 401 */ }
var claims struct {
    Name  string   `json:"name"`
    EmpNo string   `json:"emp_no"`
    Roles []string `json:"roles"`
    Sid   string   `json:"sid"`            // back-channel 로그아웃용으로 세션에 둔다
}
idToken.Claims(&claims)
```

계정 연결(`sub` → `emp_no` → JIT)은 [`linkAccount`](../../examples/integration/go/main.go), 로그인 뒤에는 세션 ID 를 새로 만든다(세션 고정 방지).

**back-channel 로그아웃** — 서명·`iss`·`aud`·`exp` 는 ID 토큰 검증기를 그대로 쓰고, 나머지는 직접 본다. `typ` 는 go-oidc 가 보지 않으므로 JOSE 헤더를 읽어 확인한다.

```go
header, _, _ := strings.Cut(raw, ".")
// base64url 디코드 → {"typ":"logout+jwt"} 인지
t, err := idVerifier.Verify(ctx, raw)
var c struct {
    Sid    string          `json:"sid"`
    Nonce  *string         `json:"nonce"`      // 있으면 거부
    Events map[string]any  `json:"events"`     // backchannel-logout 이벤트가 있어야 함
    Iat    json.RawMessage `json:"iat"`        // 있어야 함
}
```

`sid` 가 있으면 그 `sid` 를 가진 세션만, 없으면 `sub` 의 세션을 모두 지운다 ([`backchannelLogout`](../../examples/integration/go/main.go)).

**웹훅** — 받은 바이트로 HMAC 을 계산하고 `hmac.Equal` 로 상수 시간 비교한다.

```go
body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
mac := hmac.New(sha256.New, webhookSecret)
mac.Write([]byte(ts + "."))
mac.Write(body)
ok := hmac.Equal(mac.Sum(nil), got)          // got = hex.Decode("sha256=" 뒤)
```

그다음 시각(300초), `X-Didrakon-Delivery` 중복을 보고, `user.status_changed` 가 `RETIRED` 면 로컬 계정을 끄고 그 사용자의 세션을 지운다 ([`webhook`](../../examples/integration/go/main.go)).

## 5. 실행·검증

```bash
cd examples/integration/go
./run.sh                                   # go run . (포트 4105)

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4105                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4105 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **nonce 는 직접 비교한다.** `oidc.Nonce()` 는 인가 요청에 값을 넣을 뿐이고 `Verify` 는 nonce 를 보지 않는다.
- **`typ` 도 직접 본다.** 로그아웃 토큰과 ID 토큰은 같은 키로 서명되므로, `typ` 를 보지 않으면 ID 토큰을 로그아웃 토큰처럼 보내 남의 세션을 끊을 수 있다.
- 세션·사용자·처리한 전달 ID 를 메모리에 두므로 재시작하면 사라지고, 인스턴스가 여럿이면 back-channel 로그아웃이 한 인스턴스에만 닿는다. 운영에서는 세션을 Redis·DB 에, 처리한 전달 ID 는 `webhook_deliveries(delivery_id PRIMARY KEY, received_at)` 같은 테이블에 두고 오래된 행을 지운다.
- 운영에서는 issuer 와 앱 주소가 https 이고, 세션 쿠키에 `Secure: true` 를 준다. `SameSite=Lax` 여야 IAM 에서 돌아오는 `/callback` 에 쿠키가 붙는다.
- `oauth2.Config.Exchange` 는 기본 `http.DefaultClient` 를 쓴다. 타임아웃을 주려면 `ctx` 에 `oauth2.HTTPClient` 로 클라이언트를 넣는다 (go-oidc 도 같은 `ctx` 값을 쓴다).
