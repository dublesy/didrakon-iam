import { NextResponse, type NextRequest } from "next/server";
import { SESSION_COOKIE } from "@/lib/session-cookie";

/**
 * 세션 쿠키가 없으면 로그인으로 보낸다. 쿠키 존재만 보는 빠른 검사이고,
 * 실제 검증(복호화·만료)은 서버 쪽 [getAccessToken] 이 한다.
 */
export function proxy(request: NextRequest) {
  if (request.cookies.has(SESSION_COOKIE)) return NextResponse.next();
  const login = new URL("/auth/login", request.url);
  login.searchParams.set("next", request.nextUrl.pathname + request.nextUrl.search);
  return NextResponse.redirect(login);
}

export const config = {
  // 로그인 흐름 자체와 정적 파일은 제외한다
  matcher: ["/((?!auth/|callback|login-failed|_next/|favicon.ico|icon.svg).*)"],
};
