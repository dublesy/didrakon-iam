import "server-only";
import { config, postLogoutRedirectUri, redirectUri } from "./config";
import { codeChallenge } from "./crypto";
import type { Session } from "./session";

type TokenResponse = {
  access_token: string;
  id_token?: string;
  expires_in: number;
};

export function authorizeUrl(state: string, verifier: string): string {
  const url = new URL("/oauth2/authorize", config.issuer);
  url.search = new URLSearchParams({
    response_type: "code",
    client_id: config.clientId,
    redirect_uri: redirectUri(),
    scope: "openid profile",
    state,
    code_challenge: codeChallenge(verifier),
    code_challenge_method: "S256",
  }).toString();
  return url.toString();
}

export function endSessionUrl(idToken: string | undefined): string {
  const url = new URL("/connect/logout", config.issuer);
  if (idToken) {
    url.search = new URLSearchParams({ id_token_hint: idToken, post_logout_redirect_uri: postLogoutRedirectUri() }).toString();
  }
  return url.toString();
}

export const exchangeCode = (code: string, verifier: string) =>
  tokenRequest({ grant_type: "authorization_code", code, redirect_uri: redirectUri(), code_verifier: verifier });

export class TokenError extends Error {}

/**
 * public client 라 비밀값 없이 client_id 와 PKCE verifier 로 교환한다.
 * IAM 은 public client 에 refresh token 을 주지 않으므로, 토큰이 만료되면 다시 authorize 로 보낸다
 * (IdP 로그인 세션이 살아 있으면 화면 없이 바로 돌아온다).
 */
async function tokenRequest(params: Record<string, string>): Promise<Session> {
  const response = await fetch(new URL("/oauth2/token", config.issuer), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({ ...params, client_id: config.clientId }),
    cache: "no-store",
  });
  if (!response.ok) {
    throw new TokenError(`토큰 요청 실패: ${response.status}`);
  }
  const body = (await response.json()) as TokenResponse;
  return {
    accessToken: body.access_token,
    idToken: body.id_token,
    expiresAt: Date.now() + body.expires_in * 1000,
  };
}
