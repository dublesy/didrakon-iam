import { NextResponse, type NextRequest } from "next/server";
import { randomToken } from "@/lib/crypto";
import { authorizeUrl } from "@/lib/oidc";
import { safeNext, writePendingLogin } from "@/lib/session";

/** IAM 로그인 시작. state·PKCE verifier 는 암호화 쿠키에 잠깐 두고 IAM authorize 로 보낸다 */
export async function GET(request: NextRequest) {
  const state = randomToken();
  const verifier = randomToken(48);
  await writePendingLogin({ state, verifier, next: safeNext(request.nextUrl.searchParams.get("next")) });
  return NextResponse.redirect(authorizeUrl(state, verifier));
}
