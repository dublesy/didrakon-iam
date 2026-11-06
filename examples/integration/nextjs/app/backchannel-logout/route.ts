import { verifyLogoutToken } from "@/lib/iam";
import { endSessions } from "@/lib/store";

export async function POST(request: Request) {
  let token;
  try {
    const form = await request.formData();
    token = await verifyLogoutToken(String(form.get("logout_token") ?? ""));
  } catch (e) {
    console.warn("logout_token 거부:", (e as Error).message);
    return Response.json({ error: "invalid_request" }, { status: 400 });
  }
  // sid 가 있으면 그 로그인 세션만, 없으면 그 사용자의 세션 모두
  const ended = endSessions((u) => (token.sid ? u.sid === token.sid : u.sub === token.sub));
  console.log(`back-channel 로그아웃: sub=${token.sub} sid=${token.sid ?? "-"} 세션 ${ended}개 종료`);
  return new Response(null, { status: 200, headers: { "Cache-Control": "no-store" } });
}
