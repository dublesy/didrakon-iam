import { NextResponse, type NextRequest } from "next/server";
import { config } from "@/lib/config";
import { isExpired, readSession } from "@/lib/session";

/**
 * 접근 재검토 증적 CSV 를 IAM 에서 받아 그대로 내려준다. 브라우저는 IAM 토큰을 보지 못하므로 서버가 세션의 토큰을 붙인다.
 * 권한(REVIEW 조회)은 IAM 이 판정한다.
 */
export async function GET(request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  if (!/^\d+$/.test(id)) return text("잘못된 캠페인 번호입니다", 400);

  const session = await readSession();
  if (!session || isExpired(session)) {
    return NextResponse.redirect(new URL(`/auth/login?next=${encodeURIComponent(`/access-reviews?id=${id}`)}`, request.url));
  }

  const response = await fetch(new URL(`/api/v1/access-reviews/${id}/export`, config.issuer), {
    headers: { Authorization: `Bearer ${session.accessToken}` },
    cache: "no-store",
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: { message?: string } } | null;
    return text(body?.error?.message ?? "증적을 내려받지 못했습니다", response.status);
  }
  return new NextResponse(response.body, {
    headers: {
      "Content-Type": response.headers.get("Content-Type") ?? "text/csv; charset=utf-8",
      "Content-Disposition": response.headers.get("Content-Disposition") ?? `attachment; filename="access-review-${id}.csv"`,
      "Cache-Control": "no-store",
    },
  });
}

const text = (message: string, status: number) =>
  new NextResponse(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" } });
