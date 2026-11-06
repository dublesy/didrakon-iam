// DIDRAKON IAM 연동 예제: Express + openid-client
import crypto from 'node:crypto';
import express from 'express';
import session from 'express-session';
import * as client from 'openid-client';
import { oidcConfig, settings, verifyLogoutToken, verifyWebhook } from './iam.js';
import { findBySubject, linkAccount } from './users.js';

const app = express();
// 예제라 메모리 저장소. 운영은 Redis·DB 저장소(connect-redis 등)를 쓴다. 세션이 서버에 있어야 back-channel 로그아웃으로 끝낼 수 있다
const store = new session.MemoryStore();
app.use(session({
  name: 'sample_express_sid', // localhost 는 포트가 달라도 쿠키를 함께 쓰므로 다른 앱과 겹치지 않는 이름
  secret: process.env.SESSION_SECRET ?? crypto.randomBytes(32).toString('hex'),
  store,
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', secure: settings.baseUrl.startsWith('https://') },
}));

app.get('/', (req, res) => res.type('text').send('DIDRAKON IAM 연동 예제 (Express). /login 으로 로그인한다.'));

app.get('/login', async (req, res, next) => {
  try {
    const config = await oidcConfig();
    const login = {
      state: client.randomState(),
      nonce: client.randomNonce(),
      verifier: client.randomPKCECodeVerifier(),
    };
    req.session.login = login;
    const url = client.buildAuthorizationUrl(config, {
      redirect_uri: `${settings.baseUrl}/callback`,
      scope: 'openid profile',
      state: login.state,
      nonce: login.nonce,
      code_challenge: await client.calculatePKCECodeChallenge(login.verifier),
      code_challenge_method: 'S256',
    });
    req.session.save(() => res.redirect(url.href));
  } catch (e) {
    next(e);
  }
});

app.get('/callback', async (req, res) => {
  const login = req.session.login;
  if (!login) return res.status(400).send('로그인 요청 정보가 없습니다. /login 부터 다시 하세요.');
  let tokens;
  try {
    // state 확인 → code 교환(client_secret_basic + code_verifier) → ID 토큰 검증(서명, iss, aud, exp, nonce)
    tokens = await client.authorizationCodeGrant(await oidcConfig(), new URL(req.originalUrl, settings.baseUrl), {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
  } catch (e) {
    console.warn('로그인 실패:', e.message);
    return res.status(400).send('로그인에 실패했습니다.');
  }
  const claims = tokens.claims();
  const user = linkAccount(claims);
  if (!user.active) return res.status(403).send('사용이 중지된 계정입니다.');

  // 로그인 전 세션을 버리고 새로 만든다 (세션 고정 방지)
  req.session.regenerate((err) => {
    if (err) return res.status(500).end();
    req.session.user = {
      sub: claims.sub,
      sid: claims.sid ?? null, // back-channel 로그아웃이 이 값으로 세션을 찾는다
      name: claims.name ?? null,
      empNo: claims.emp_no ?? null,
      roles: claims.roles ?? [],
      localUserId: user.id,
      idToken: tokens.id_token,
    };
    req.session.save(() => res.redirect('/me'));
  });
});

app.get('/me', (req, res) => {
  const u = req.session.user;
  if (!u || !findBySubject(u.sub)?.active) return res.status(401).json({ error: 'unauthorized' });
  const { sub, name, empNo, roles, localUserId, sid } = u;
  res.json({ sub, name, empNo, roles, localUserId, sid });
});

app.get('/logout', async (req, res) => {
  const idToken = req.session.user?.idToken;
  req.session.destroy(async () => {
    res.clearCookie('sample_express_sid');
    if (!idToken) return res.redirect('/');
    const url = client.buildEndSessionUrl(await oidcConfig(), {
      id_token_hint: idToken,
      post_logout_redirect_uri: `${settings.baseUrl}/`,
    });
    res.redirect(url.href);
  });
});

/** 조건에 맞는 서버 세션을 모두 지운다 */
function endSessions(match) {
  return new Promise((resolve, reject) => {
    store.all((err, sessions) => {
      if (err) return reject(err);
      const ids = Object.entries(sessions ?? {}).filter(([, s]) => s.user && match(s.user)).map(([id]) => id);
      Promise.all(ids.map((id) => new Promise((r) => store.destroy(id, r)))).then(() => resolve(ids.length));
    });
  });
}

app.post('/backchannel-logout', express.urlencoded({ extended: false }), async (req, res) => {
  let token;
  try {
    token = await verifyLogoutToken(req.body?.logout_token);
  } catch (e) {
    console.warn('logout_token 거부:', e.message);
    return res.status(400).json({ error: 'invalid_request' });
  }
  // sid 가 있으면 그 로그인 세션만, 없으면 그 사용자의 세션 모두
  const ended = await endSessions((u) => (token.sid ? u.sid === token.sid : u.sub === token.sub));
  console.log(`back-channel 로그아웃: sub=${token.sub} sid=${token.sid ?? '-'} 세션 ${ended}개 종료`);
  res.set('Cache-Control', 'no-store').status(200).end();
});

// 처리한 전달 ID. 예제라 메모리. 운영은 DB 테이블(delivery_id 를 기본 키로)에 둔다
const processedDeliveries = new Set();

// 서명은 받은 바이트 그대로 계산해야 하므로 이 경로만 express.raw 로 받는다 (express.json 을 앞에 두지 않는다)
app.post('/webhooks/iam', express.raw({ type: '*/*', limit: '1mb' }), async (req, res) => {
  const raw = Buffer.isBuffer(req.body) ? req.body : Buffer.alloc(0);
  if (!verifyWebhook(raw, req.get('X-Didrakon-Timestamp'), req.get('X-Didrakon-Signature'))) {
    return res.status(401).json({ error: 'invalid signature' });
  }
  const delivery = req.get('X-Didrakon-Delivery');
  if (processedDeliveries.has(delivery)) return res.status(200).json({ duplicate: true });

  const event = JSON.parse(raw.toString('utf8'));
  if (event.type === 'user.status_changed' && event.data?.status === 'RETIRED') {
    const user = findBySubject(event.data.subjectId);
    if (user) user.active = false; // 계정 끄기 (실제 시스템은 권한도 모두 회수)
    await endSessions((u) => u.sub === String(event.data.subjectId));
  }
  processedDeliveries.add(delivery);
  res.status(200).json({ ok: true });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).send('오류가 발생했습니다.');
});

const port = Number(process.env.PORT ?? 4102);
app.listen(port, () => console.log(`Express 예제: ${settings.baseUrl} (IAM ${settings.issuer}, client ${settings.clientId})`));
