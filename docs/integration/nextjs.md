# Next.js (App Router) 빠른 시작

Next.js 앱을 DIDRAKON IAM 에 붙이는 방법. 로그인은 서버의 route handler 에서 처리하고 세션은 서버에 둔다. 토큰 claim, back-channel 로그아웃·웹훅 규칙은 [연동 가이드](README.md)에 있고, 여기에는 Next.js 코드만 둔다. 예제: [`examples/integration/nextjs/`](../../examples/integration/nextjs/)

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Node.js | 20.19 이상 (예제는 24 로 확인) |
| `next` | 16.4.5 (App Router, route handler 만 쓴다) |
| `react`, `react-dom` | 19.3.1 |
| `openid-client` | 6.8.9 (discovery, PKCE, ID 토큰 검증) |
| `jose` | 6.2.15 (back-channel 로그아웃 토큰 검증) |
| `typescript` | 5.9.3 (개발용) |

```bash
npm install next@16.4.5 react@19.3.1 react-dom@19.3.1 openid-client@6.8.9 jose@6.2.15
```

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-nextjs` |
| 유형 | `WEB`, 기밀 (토큰 교환을 서버에서 하므로) |
| 리다이렉트 URI | `http://localhost:4103/callback` |
| 로그아웃 후 돌아갈 주소 | `http://localhost:4103/` |
| 로그아웃 알림 주소 | `http://localhost:4103/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 예제 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 | `sample-nextjs`, 임시값 |
| `APP_BASE_URL` | 이 앱 주소 (redirect URI 를 만든다) | `http://localhost:4103` |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | |

모두 서버에서만 읽는다. `NEXT_PUBLIC_` 을 붙이면 비밀값이 브라우저 번들에 들어가므로 붙이지 않는다. `run.sh` 는 `../.env.local` 의 `NEXTJS_CLIENT_ID`·`NEXTJS_CLIENT_SECRET` 를 `CLIENT_ID`·`CLIENT_SECRET` 로 넘긴다.

openid-client 는 http issuer 를 거부한다. 예제는 issuer 가 `localhost` 일 때만 `allowInsecureRequests` 를 켠다. **운영 IAM 은 https 이므로 이 옵션을 쓰지 않는다.**

## 4. 핵심 코드

| 파일 | 하는 일 |
|---|---|
| [`lib/iam.ts`](../../examples/integration/nextjs/lib/iam.ts) | discovery, logout_token 검증, 웹훅 서명 검증 |
| [`lib/store.ts`](../../examples/integration/nextjs/lib/store.ts) | 서버 세션(`Map`), 로컬 사용자·계정 연결 |
| [`app/login/route.ts`](../../examples/integration/nextjs/app/login/route.ts), [`app/callback/route.ts`](../../examples/integration/nextjs/app/callback/route.ts) | 로그인 |
| [`app/me/route.ts`](../../examples/integration/nextjs/app/me/route.ts), [`app/logout/route.ts`](../../examples/integration/nextjs/app/logout/route.ts) | 세션 확인, 로그아웃 |
| [`app/backchannel-logout/route.ts`](../../examples/integration/nextjs/app/backchannel-logout/route.ts) | back-channel 로그아웃 |
| [`app/webhooks/iam/route.ts`](../../examples/integration/nextjs/app/webhooks/iam/route.ts) | 웹훅 |

### 세션

쿠키에는 무작위 세션 ID 만 두고(`httpOnly`), 내용은 서버 `Map` 에 둔다. 로그인 전(`state`·`nonce`·`verifier`)과 로그인 후 세션을 다른 ID 로 만들어 세션 고정을 막는다. Next.js 는 경로마다 모듈을 따로 읽을 수 있어 저장소를 `globalThis` 에 하나만 둔다.

### 로그인 (`/login`, `/callback`)

```ts
// app/login/route.ts
const login = { state: client.randomState(), nonce: client.randomNonce(), verifier: client.randomPKCECodeVerifier() };
const url = client.buildAuthorizationUrl(await oidcConfig(), {
  redirect_uri: `${settings.baseUrl}/callback`, scope: "openid profile", state: login.state, nonce: login.nonce,
  code_challenge: await client.calculatePKCECodeChallenge(login.verifier), code_challenge_method: "S256",
});
const response = NextResponse.redirect(url, 302);
startSession(response, { login });

// app/callback/route.ts: state 확인, code 교환(client_secret_basic + code_verifier), ID 토큰 검증을 한 번에
const currentUrl = new URL(`/callback${request.nextUrl.search}`, settings.baseUrl);
const tokens = await client.authorizationCodeGrant(await oidcConfig(), currentUrl, {
  pkceCodeVerifier: login.verifier, expectedState: login.state, expectedNonce: login.nonce, idTokenExpected: true,
});
const claims = tokens.claims()!;
const user = linkAccount(claims);   // sub → emp_no → JIT
startSession(response, { user: { sub: claims.sub, sid: claims.sid, ..., localUserId: user.id, idToken: tokens.id_token } });
```

`currentUrl` 은 `request.url` 대신 `APP_BASE_URL` 로 만든다. 프록시 뒤에서는 `request.url` 의 호스트가 등록한 redirect URI 와 달라 교환이 실패할 수 있다.

### 계정 연결

[`lib/store.ts`](../../examples/integration/nextjs/lib/store.ts) 의 `linkAccount`: `iam_subject_id` 로 찾고, 없으면 `emp_no` 로 찾아 연결하고, 그래도 없으면 만든다(JIT). 실제 시스템은 users 테이블의 `iam_subject_id` 컬럼을 쓴다 ([데이터 이관 가이드](database.md)).

### back-channel 로그아웃 (`POST /backchannel-logout`)

```ts
const form = await request.formData();
const { payload } = await jwtVerify(String(form.get("logout_token")), createRemoteJWKSet(new URL(jwks_uri)), {
  issuer, audience: clientId, typ: "logout+jwt", algorithms: ["RS256"], requiredClaims: ["iat", "exp"],
});
// events 에 back-channel-logout 이 있고 nonce 가 없는지 확인
endSessions((u) => (payload.sid ? u.sid === payload.sid : u.sub === payload.sub));
return new Response(null, { status: 200 });   // 검증 실패는 400
```

### 웹훅 (`POST /webhooks/iam`)

```ts
export const runtime = "nodejs";
const raw = Buffer.from(await request.arrayBuffer());   // 받은 바이트 그대로
if (!verifyWebhook(raw, h.get("X-Didrakon-Timestamp"), h.get("X-Didrakon-Signature"))) return 401;
if (deliveries.has(delivery)) return 200;                // 중복
// user.status_changed + RETIRED → 로컬 계정 끄고 그 사용자의 세션 종료
```

## 5. 실행·검증

```bash
cd examples/integration/nextjs
./run.sh            # next build 후 next start (http://localhost:4103)
./run.sh dev        # next dev
python3 ../verify.py http://localhost:4103                  # 로그인·웹훅·back-channel 로그아웃
python3 ../verify.py http://localhost:4103 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **Node 런타임**: `node:crypto`(HMAC, `timingSafeEqual`)와 openid-client 를 쓰는 route handler 는 Node 런타임이어야 한다. `export const runtime = "edge"` 를 붙이거나 middleware(proxy)에서 토큰을 검증하지 않는다.
- **웹훅 원본 바이트**: `request.json()` 으로 읽고 `JSON.stringify` 로 다시 만들면 서명이 맞지 않는다. `arrayBuffer()` 로 읽는다.
- **메모리 세션**: 예제의 `Map` 은 재시작하면 사라지고, 인스턴스가 여럿(서버리스, 여러 컨테이너)이면 back-channel 로그아웃이 다른 인스턴스에 닿아 세션이 남는다. 운영은 Redis·DB 에 세션을 두고, `sid`·`sub` 로 찾을 수 있게 색인한다.
- **세션을 쿠키에만 담지 않는다**: 암호화한 쿠키 세션(iron-session, Auth.js 의 JWT 세션 등)은 서버가 끝낼 수 없어 back-channel 로그아웃을 받을 수 없다. Auth.js 를 쓴다면 DB 세션 전략으로 바꾼다.
- **처리한 전달 ID**: 예제는 메모리 `Set`. 운영은 `delivery_id` 를 기본 키로 한 테이블에 둔다.
- **캐시**: 세션을 읽는 GET route handler 가 정적으로 렌더링되지 않게 한다. 예제는 쿠키·요청을 읽어 동적으로 처리된다(`next build` 출력의 `ƒ`).
- **쿠키 이름**: localhost 는 포트가 달라도 쿠키를 함께 쓰므로 다른 로컬 앱과 겹치지 않는 이름(`sample_nextjs_sid`)을 쓴다.
