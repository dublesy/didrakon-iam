import "server-only";
import { redirect } from "next/navigation";
import { connection } from "next/server";
import { config } from "./config";
import { isExpired, readSession } from "./session";

/** IAM API 공통 응답을 성공·실패로 나눈 결과 */
export type ApiResult<T> = { ok: true; data: T } | { ok: false; status: number; code: string; message: string };

type Envelope<T> = { success: boolean; data: T | null; error: { code: string; message: string } | null };

/**
 * 서버 컴포넌트·서버 액션에서 IAM API 를 부른다. 토큰은 서버에서만 붙인다.
 * 세션이 없거나 토큰이 만료되었으면 다시 로그인하게 하고, 끝나면 [returnTo] 로 돌아온다.
 */
export async function callIam<T>(path: string, init: RequestInit = {}, returnTo = "/"): Promise<ApiResult<T>> {
  // 만료 확인(현재 시각)은 사전 렌더링이 아니라 요청 시점에 해야 한다
  await connection();
  const session = await readSession();
  if (!session || isExpired(session)) {
    redirect(`/auth/login?next=${encodeURIComponent(returnTo)}`);
  }

  const response = await fetch(new URL(path, config.issuer), {
    ...init,
    headers: { ...init.headers, Authorization: `Bearer ${session.accessToken}`, "Content-Type": "application/json" },
    cache: "no-store",
  });
  const body = (await response.json().catch(() => null)) as Envelope<T> | null;

  // 토큰을 IAM 이 받지 않으면(서명 키 교체·폐기 등) 다시 로그인한다. MFA 부족은 화면에서 안내한다
  if (response.status === 401 && body?.error?.code !== "MFA_REQUIRED") {
    redirect(`/auth/login?next=${encodeURIComponent(returnTo)}`);
  }

  if (response.ok && body?.success) return { ok: true, data: body.data as T };
  return {
    ok: false,
    status: response.status,
    code: body?.error?.code ?? "UNKNOWN",
    message: body?.error?.message ?? "요청을 처리하지 못했습니다",
  };
}
