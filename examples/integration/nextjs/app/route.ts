// 로그아웃 뒤 돌아오는 곳 (post_logout_redirect_uri)
export function GET() {
  return new Response("DIDRAKON IAM 연동 예제 (Next.js). /login 으로 로그인한다.", {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
}
