# .NET (ASP.NET Core) 빠른 시작

ASP.NET Core 의 OpenIdConnect 인증 핸들러로 IAM 에 붙는 방법. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고, 여기에는 .NET 에서 하는 법만 둔다.

예제: [`examples/integration/dotnet/`](../../examples/integration/dotnet/) (포트 4108, Docker 로 실행)

## 1. 준비물

| 항목 | 버전 |
|---|---|
| .NET | 10 (LTS). SDK 10.0.403, 런타임 10.0.14 |
| 패키지 | `Microsoft.AspNetCore.Authentication.OpenIdConnect` 10.0.14 (JWT 검증 `Microsoft.IdentityModel.*` 8.19 가 함께 온다) |
| 실행 | Docker (`mcr.microsoft.com/dotnet/sdk:10.0` 로 빌드, `aspnet:10.0` 로 실행) |

.NET 8·9 도 코드는 같다. 다만 `Convert.ToHexStringLower` 는 9 부터 있다 (8 에서는 `Convert.ToHexString(...).ToLowerInvariant()`).

## 2. IAM 클라이언트 등록 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-dotnet` |
| 유형 | `WEB`, 기밀 |
| 리다이렉트 URI | `http://localhost:4108/callback` |
| 로그아웃 알림 주소 | `http://localhost:4108/backchannel-logout` |

핸들러의 기본 콜백은 `/signin-oidc` 다. 예제는 `CallbackPath = "/callback"` 으로 바꿨다.

## 3. 설정

| 환경변수 | 뜻 |
|---|---|
| `IAM_ISSUER` | `http://localhost:8080` |
| `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET` | 등록할 때 받은 값. `run.sh` 가 `.env.local` 의 `DOTNET_CLIENT_ID`·`DOTNET_CLIENT_SECRET` 를 넘긴다 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값. 없으면 시작하지 않는다 |

컨테이너 안에서도 IAM 이 `http://localhost:8080` 이어야 토큰의 `iss` 와 맞는다. [`Dockerfile`](../../examples/integration/dotnet/Dockerfile)은 `socat` 으로 컨테이너의 `localhost:8080` 을 호스트로 넘긴다.

## 4. 핵심 코드

모두 [`Program.cs`](../../examples/integration/dotnet/Program.cs)에 있다.

### 로그인·콜백

```csharp
builder.Services.AddAuthentication(o => { o.DefaultScheme = Cookie; o.DefaultChallengeScheme = Oidc; })
    .AddCookie(o =>
    {
        o.SessionStore = sessions;                      // 쿠키에는 세션 키만
        o.Events.OnRedirectToLogin = ctx => { ctx.Response.StatusCode = 401; return Task.CompletedTask; };
    })
    .AddOpenIdConnect(o =>
    {
        o.Authority = issuer;
        o.ClientId = clientId; o.ClientSecret = clientSecret;
        o.ResponseType = "code";
        o.ResponseMode = "query";
        o.UsePkce = true;
        o.SaveTokens = true;                            // 로그아웃 id_token_hint
        o.CallbackPath = "/callback";
        o.Scope.Clear(); o.Scope.Add("openid"); o.Scope.Add("profile");
        o.MapInboundClaims = false;                     // sub·sid·roles 이름 그대로
    });

app.MapGet("/login", () => Results.Challenge(new() { RedirectUri = "/me" }, [Oidc]));
app.MapGet("/logout", () => Results.SignOut(new(), [Cookie, Oidc]));
```

- `state`·`nonce`·PKCE(S256)는 핸들러가 만들고 확인한다.
- ID 토큰 검증(JWKS 서명, `iss`, `aud`=`ClientId`, `exp`, `nonce`)도 핸들러가 한다.
- 계정 연결은 검증이 끝난 뒤 `OnTokenValidated` 에서 한다. 연결한 로컬 ID 를 `local_user_id` claim 으로 세션에 넣는다.

### client_secret_basic

이 핸들러는 토큰 요청에 비밀값을 **본문(`client_secret_post`)으로만** 보낸다. IAM 등록값(`client_secret_basic`)에 맞추려고 예제는 본문에서 빼고 헤더로 보낸다.

```csharp
o.BackchannelHttpHandler = new ClientSecretBasicHandler(clientId, clientSecret);  // POST 에 Basic 헤더
o.Events.OnAuthorizationCodeReceived = ctx =>
{
    ctx.TokenEndpointRequest!.ClientId = null;
    ctx.TokenEndpointRequest.ClientSecret = null;
    return Task.CompletedTask;
};
```

IAM 은 `client_secret_post` 도 받는다. 이 부분이 번거로우면 빼도 동작한다.

### 계정 연결 — [`LocalUsers.cs`](../../examples/integration/dotnet/LocalUsers.cs)

```csharp
var user = _users.FirstOrDefault(u => u.IamSubjectId == sub)                                   // iam_subject_id
    ?? _users.FirstOrDefault(u => u.IamSubjectId == null && empNo != null && u.EmpNo == empNo); // 사번
if (user == null) { user = new LocalUser(++_seq, null, empNo, name); _users.Add(user); }       // JIT
user.IamSubjectId = sub;
```

로컬 계정이 꺼져 있으면(퇴사 처리) `ctx.Fail(...)` 로 로그인을 막는다.

### 서버 세션 — [`SessionStore.cs`](../../examples/integration/dotnet/SessionStore.cs)

쿠키 인증은 기본으로 로그인 정보 전체를 암호화해 쿠키에 담는다. 그러면 back-channel 로그아웃으로 끝낼 수 없다. `ITicketStore` 를 붙이면 쿠키에는 키만 남고 정보는 서버에 있다. 세션을 지우면 다음 요청부터 그 쿠키는 로그인이 아니다.

```csharp
public int End(string? sub, string? sid) =>   // sid 가 있으면 그 세션, 없으면 sub 의 모든 세션
    /* 저장된 ticket 의 Principal 에서 sid·sub claim 을 비교해 지운다 */;
```

### back-channel 로그아웃

```csharp
var config = await oidcOptions.Get(Oidc).ConfigurationManager!.GetConfigurationAsync(ct);   // JWKS 재사용
var result = await new JsonWebTokenHandler().ValidateTokenAsync(token, new TokenValidationParameters
{
    ValidIssuer = issuer, ValidAudience = clientId,
    IssuerSigningKeys = config.SigningKeys,
    ValidTypes = ["logout+jwt"],               // 헤더 typ
    RequireExpirationTime = true,
});
// 이어서 events 에 back-channel 이벤트, iat 있음, nonce 없음, sub 또는 sid 있음을 확인
```

실패하면 `400`, 통과하면 `sessions.End(sub, sid)` 후 `200`.

### 웹훅

```csharp
using var buffer = new MemoryStream();
await req.Body.CopyToAsync(buffer);                // 받은 바이트 그대로
var expected = "sha256=" + Convert.ToHexStringLower(HMACSHA256.HashData(key, ts + "." + body));
if (!CryptographicOperations.FixedTimeEquals(expected, signature)) return 401;   // 상수 시간
if (Math.Abs(now - ts) > 300) return 401;
if (!processed.TryAdd(delivery, true)) return Ok(duplicate);                     // 실제로는 DB 테이블
// user.status_changed + RETIRED → users.Disable(sub); sessions.End(sub, null);
```

중복 거르기는 예제라 메모리다. 실제로는 `webhook_delivery(delivery_id PRIMARY KEY, received_at)` 같은 테이블에 넣는다.

## 5. 실행·검증

```bash
cd examples/integration/dotnet
./run.sh                                   # 이미지를 만들고 4108 로 띄운다 (Ctrl+C 로 끝)
python3 ../verify.py http://localhost:4108
```

클라이언트를 등록하기 전에는 웹훅만 확인할 수 있다: `python3 ../verify.py http://localhost:4108 --webhook-only`

## 6. 주의할 점

- **`ResponseMode` 기본값은 `form_post` 다.** 예제는 `query` 로 둔다. `form_post` 를 쓰면 IdP 에서 POST 로 돌아오므로 상관(correlation)·nonce 쿠키가 `SameSite=None; Secure` 여야 하고 https 가 필요하다.
- **http 로컬에서는 상관·nonce 쿠키가 버려진다.** 기본값이 `Secure` 라서다. 예제는 `SecurePolicy = SameAsRequest`, `SameSite = Lax` 로 바꿨다. 운영(https)에서는 기본값을 쓴다.
- **`MapInboundClaims = false` 를 켠다.** 끄지 않으면 `sub` 가 `http://schemas.xmlsoap.org/.../nameidentifier` 같은 긴 이름으로 바뀌어 `sid`·`roles` 를 찾기 어렵다.
- **로그아웃 순서는 `Cookie`, `Oidc`.** OIDC 로그아웃이 세션에 저장한 `id_token` 을 `id_token_hint` 로 보낸다 (`SaveTokens = true` 필요). 핸들러는 `post_logout_redirect_uri` 를 늘 붙이므로, 등록하지 않았으면 예제처럼 `OnRedirectToIdentityProviderForSignOut` 에서 지운다.
- **세션 저장소가 메모리다.** 서버가 여러 대면 `IDistributedCache`(Redis 등)로 `ITicketStore` 를 만들고 `sub`·`sid` 로 찾을 색인을 함께 둔다. 만료된 세션도 정리한다 (예제는 정리하지 않는다).
- **Data Protection 키가 컨테이너 안에 있다.** 컨테이너를 다시 띄우면 기존 쿠키를 읽지 못한다. 운영은 키를 공유 저장소에 둔다 (`PersistKeysTo...`).
- **웹훅 본문을 모델 바인딩으로 받지 않는다.** `[FromBody]` 객체를 다시 직렬화하면 서명이 맞지 않는다.
