# Node.js (Express) 빠른 시작

Express 앱을 DIDRAKON IAM 에 붙이는 방법. 토큰 claim, back-channel 로그아웃·웹훅 규칙은 [연동 가이드](README.md)에 있고, 여기에는 Express 코드만 둔다. 예제: [`examples/integration/express/`](../../examples/integration/express/)

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Node.js | 20.19 이상 (예제는 24 로 확인) |
| `express` | 5.3.0 |
| `express-session` | 1.19.0 |
| `openid-client` | 6.8.9 (ESM. discovery, PKCE, ID 토큰 검증) |
| `jose` | 6.2.15 (back-channel 로그아웃 토큰 검증) |

```bash
npm install express@5.3.0 express-session@1.19.0 openid-client@6.8.9 jose@6.2.15
```

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-express` |
| 유형 | `WEB`, 기밀 |
| 리다이렉트 URI | `http://localhost:4102/callback` |
| 로그아웃 후 돌아갈 주소 | `http://localhost:4102/` |
| 로그아웃 알림 주소 | `http://localhost:4102/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 예제 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 | `sample-express`, 임시값 |
| `APP_BASE_URL` | 이 앱 주소 (redirect URI 를 만든다) | `http://localhost:4102` |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | |
| `SESSION_SECRET` | 세션 쿠키 서명 비밀값 | 없으면 기동할 때마다 무작위 |

`run.sh` 는 `../.env.local` 의 `EXPRESS_CLIENT_ID`·`EXPRESS_CLIENT_SECRET` 를 `CLIENT_ID`·`CLIENT_SECRET` 로 넘긴다.

openid-client 는 http issuer 를 거부한다. 예제는 issuer 가 `localhost` 일 때만 `allowInsecureRequests` 를 켠다. **운영 IAM 은 https 이므로 이 옵션을 쓰지 않는다.**

## 4. 핵심 코드

파일은 셋이다: [`app.js`](../../examples/integration/express/app.js)(경로), [`iam.js`](../../examples/integration/express/iam.js)(OIDC 설정·토큰·서명 검증), [`users.js`](../../examples/integration/express/users.js)(계정 연결).

### 로그인 (`/login`, `/callback`)

```js
// iam.js: discovery 는 처음 쓸 때 한 번
client.discovery(new URL(issuer), clientId, undefined, client.ClientSecretBasic(clientSecret),
  isLocalhost ? { execute: [client.allowInsecureRequests] } : undefined);

// /login: state·nonce·PKCE 를 세션에 두고 보낸다
req.session.login = { state: client.randomState(), nonce: client.randomNonce(), verifier: client.randomPKCECodeVerifier() };
const url = client.buildAuthorizationUrl(config, {
  redirect_uri: `${baseUrl}/callback`, scope: 'openid profile', state, nonce,
  code_challenge: await client.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256',
});

// /callback: state 확인, code 교환, ID 토큰 검증(서명·iss·aud·exp·nonce)을 한 번에
const tokens = await client.authorizationCodeGrant(config, new URL(req.originalUrl, baseUrl), {
  pkceCodeVerifier: login.verifier, expectedState: login.state, expectedNonce: login.nonce, idTokenExpected: true,
});
const claims = tokens.claims();
```

로그인에 성공하면 `req.session.regenerate()` 로 세션 ID 를 바꾸고(세션 고정 방지), ID 토큰의 `sid` 를 세션에 둔다. back-channel 로그아웃이 이 값으로 세션을 찾는다.

### 계정 연결

```js
let user = users.find((u) => u.iamSubjectId === sub);                 // 1. IAM sub
if (!user && claims.emp_no) {                                          // 2. 사번으로 찾아 연결
  user = users.find((u) => u.iamSubjectId === null && u.empNo === claims.emp_no);
  if (user) user.iamSubjectId = sub;
}
if (!user) user = createUser(...);                                     // 3. JIT
```

실제 시스템은 users 테이블의 `iam_subject_id` 컬럼을 쓴다 ([데이터 이관 가이드](database.md)).

### back-channel 로그아웃 (`POST /backchannel-logout`)

openid-client 는 logout_token 을 검증하지 않으므로 `jose` 로 한다.

```js
const { payload } = await jwtVerify(token, createRemoteJWKSet(new URL(jwks_uri)), {
  issuer, audience: clientId, typ: 'logout+jwt', algorithms: ['RS256'], requiredClaims: ['iat', 'exp'],
});
if (typeof payload.events?.['http://schemas.openid.net/event/backchannel-logout'] !== 'object') throw ...;
if ('nonce' in payload) throw ...;

// sid 가 있으면 그 세션만, 없으면 sub 의 세션 모두
store.all((err, sessions) => /* 맞는 세션 id 를 골라 store.destroy(id) */);
```

검증에 실패하면 `400`, 처리했으면 `200`. 이 요청은 IAM 서버가 보내므로 쿠키가 없다. 세션 저장소를 직접 뒤져 지운다.

### 웹훅 (`POST /webhooks/iam`)

서명은 받은 바이트 그대로 계산해야 하므로 이 경로에만 `express.raw()` 를 건다. 앱 전체에 `express.json()` 을 먼저 걸면 본문이 객체로 바뀌어 원래 바이트를 잃는다.

```js
app.post('/webhooks/iam', express.raw({ type: '*/*' }), async (req, res) => {
  // HMAC-SHA256(secret, timestamp + "." + 원본 바이트), timingSafeEqual 로 비교, 시각 ±300초
  if (!verifyWebhook(req.body, req.get('X-Didrakon-Timestamp'), req.get('X-Didrakon-Signature'))) return res.status(401)...;
  if (processedDeliveries.has(delivery)) return res.status(200)...;   // 중복
  // user.status_changed + RETIRED → 로컬 계정 끄고 그 사용자의 세션 종료
});
```

## 5. 실행·검증

```bash
cd examples/integration/express
./run.sh                                         # http://localhost:4102
python3 ../verify.py http://localhost:4102       # 로그인·웹훅·back-channel 로그아웃
python3 ../verify.py http://localhost:4102 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **웹훅 원본 바이트**: `express.json()` 으로 파싱한 뒤 `JSON.stringify` 로 다시 만들면 공백·키 순서가 달라 서명이 맞지 않는다.
- **세션 저장소**: 예제의 `MemoryStore` 는 재시작하면 사라지고 인스턴스끼리 나누지 못한다. 운영은 Redis(`connect-redis`)나 DB 저장소를 쓴다. back-channel 로그아웃은 저장소에서 `sub`·`sid` 로 세션을 찾아야 하므로, 세션이 많으면 `sid → 세션 ID` 색인을 따로 둔다.
- **처리한 전달 ID**: 예제는 메모리 `Set`. 운영은 `delivery_id` 를 기본 키로 한 테이블에 두고 처리와 같은 트랜잭션에 넣는다.
- **쿠키 이름**: localhost 는 포트가 달라도 쿠키를 함께 쓴다. 기본 이름 `connect.sid` 를 쓰면 다른 로컬 앱과 겹칠 수 있다.
- **프록시 뒤**: https 를 끝내는 프록시 뒤에서는 `app.set('trust proxy', 1)` 와 `cookie.secure: true` 를 쓴다.
