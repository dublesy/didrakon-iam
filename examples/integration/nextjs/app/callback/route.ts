import { NextResponse, type NextRequest } from "next/server";
import * as client from "openid-client";
import { oidcConfig, settings } from "@/lib/iam";
import { deleteSession, getSession, linkAccount, startSession } from "@/lib/store";

export async function GET(request: NextRequest) {
  const pending = getSession(request);
  const login = pending?.login;
  if (!pending || !login) return new Response("로그인 요청 정보가 없습니다. /login 부터 다시 하세요.", { status: 400 });
  deleteSession(pending.id); // state 는 한 번만 쓴다

  let tokens;
  try {
    // state 확인 → code 교환(client_secret_basic + code_verifier) → ID 토큰 검증(서명, iss, aud, exp, nonce)
    const currentUrl = new URL(`/callback${request.nextUrl.search}`, settings.baseUrl);
    tokens = await client.authorizationCodeGrant(await oidcConfig(), currentUrl, {
      pkceCodeVerifier: login.verifier,
      expectedState: login.state,
      expectedNonce: login.nonce,
      idTokenExpected: true,
    });
  } catch (e) {
    console.warn("로그인 실패:", (e as Error).message);
    return new Response("로그인에 실패했습니다.", { status: 400 });
  }
  const claims = tokens.claims()!;
  const user = linkAccount(claims);
  if (!user.active) return new Response("사용이 중지된 계정입니다.", { status: 403 });

  const response = NextResponse.redirect(`${settings.baseUrl}/me`, 302);
  // 로그인 전 세션은 지웠고 새 ID 로 만든다 (세션 고정 방지)
  startSession(response, {
    user: {
      sub: claims.sub,
      sid: typeof claims.sid === "string" ? claims.sid : null,
      name: typeof claims.name === "string" ? claims.name : null,
      empNo: typeof claims.emp_no === "string" ? claims.emp_no : null,
      roles: Array.isArray(claims.roles) ? (claims.roles as string[]) : [],
      localUserId: user.id,
      idToken: tokens.id_token!,
    },
  });
  return response;
}
