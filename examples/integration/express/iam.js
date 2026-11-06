// IAM 연동에 필요한 것: OIDC 설정(discovery), back-channel 로그아웃 토큰 검증, 웹훅 서명 검증
import crypto from 'node:crypto';
import * as client from 'openid-client';
import { createRemoteJWKSet, jwtVerify } from 'jose';

export const settings = {
  issuer: process.env.IAM_ISSUER ?? 'http://localhost:8080',
  clientId: process.env.CLIENT_ID ?? 'sample-express',
  clientSecret: process.env.CLIENT_SECRET ?? 'change-me',
  baseUrl: process.env.APP_BASE_URL ?? 'http://localhost:4102',
  webhookSecret: process.env.WEBHOOK_SECRET ?? '',
};

const LOGOUT_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const WEBHOOK_TOLERANCE_SECONDS = 300;

// discovery 는 처음 쓸 때 한 번 한다 (IAM 이 늦게 떠도 앱은 뜬다). 실패하면 다음 요청에서 다시 한다
let configPromise;
export function oidcConfig() {
  configPromise ??= client
    .discovery(
      new URL(settings.issuer),
      settings.clientId,
      undefined,
      client.ClientSecretBasic(settings.clientSecret),
      // openid-client 는 http issuer 를 거부한다. 로컬 개발(http://localhost)에서만 허용하고, 운영은 https 를 쓴다
      new URL(settings.issuer).hostname === 'localhost' ? { execute: [client.allowInsecureRequests] } : undefined,
    )
    .catch((e) => {
      configPromise = undefined;
      throw e;
    });
  return configPromise;
}

let jwks;
/** logout_token 을 검증하고 payload 를 돌려준다. 잘못됐으면 예외 */
export async function verifyLogoutToken(token) {
  const config = await oidcConfig();
  jwks ??= createRemoteJWKSet(new URL(config.serverMetadata().jwks_uri));
  const { payload } = await jwtVerify(token, jwks, {
    issuer: config.serverMetadata().issuer,
    audience: settings.clientId,
    typ: 'logout+jwt',
    algorithms: ['RS256'],
    requiredClaims: ['iat', 'exp'],
  });
  if (!payload.events || typeof payload.events[LOGOUT_EVENT] !== 'object') throw new Error('events 에 back-channel 로그아웃이 없다');
  if ('nonce' in payload) throw new Error('logout_token 에 nonce 가 있으면 안 된다');
  if (!payload.sub && !payload.sid) throw new Error('sub 도 sid 도 없다');
  return payload;
}

/** 웹훅 서명·시각 확인. rawBody 는 받은 바이트 그대로(Buffer) */
export function verifyWebhook(rawBody, timestamp, signature) {
  const ts = Number(timestamp);
  if (!Number.isInteger(ts) || Math.abs(Date.now() / 1000 - ts) > WEBHOOK_TOLERANCE_SECONDS) return false;
  const expected = 'sha256=' + crypto.createHmac('sha256', settings.webhookSecret)
    .update(`${timestamp}.`).update(rawBody).digest('hex');
  const a = Buffer.from(expected);
  const b = Buffer.from(String(signature ?? ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
