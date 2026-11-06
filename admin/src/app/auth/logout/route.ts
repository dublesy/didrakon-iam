import { NextResponse } from "next/server";
import { endSessionUrl } from "@/lib/oidc";
import { clearSession, readSession } from "@/lib/session";

/**
 * 콘솔 세션을 지우고 IAM 로그아웃(/connect/logout)으로 보내 IdP 로그인 세션까지 닫는다.
 * 세션 쿠키가 SameSite=Lax 라 다른 사이트의 POST 로는 로그아웃시킬 수 없다.
 */
export async function POST() {
  const session = await readSession();
  await clearSession();
  return NextResponse.redirect(endSessionUrl(session?.idToken), 303);
}
