import { NextResponse, type NextRequest } from "next/server";
import { config } from "@/lib/config";
import { exchangeCode } from "@/lib/oidc";
import { takePendingLogin, writeSession } from "@/lib/session";

/** IAM 이 돌려준 code 를 토큰으로 바꿔 세션을 만든다. 경로는 IAM 에 등록한 redirect_uri 와 같아야 한다 */
export async function GET(request: NextRequest) {
  const params = request.nextUrl.searchParams;
  const pending = await takePendingLogin();
  const code = params.get("code");

  if (params.get("error") || !pending || !code || params.get("state") !== pending.state) {
    // state 가 다르면 다른 사이트가 시작한 로그인일 수 있으므로 세션을 만들지 않는다
    return NextResponse.redirect(new URL("/login-failed", config.appUrl));
  }

  await writeSession(await exchangeCode(code, pending.verifier));
  // safeNext 로 거른 값이지만, 이동 직전에도 이 콘솔 주소인지 다시 본다
  const target = new URL(pending.next, config.appUrl);
  const home = new URL("/", config.appUrl);
  return NextResponse.redirect(target.origin === home.origin ? target : home);
}
