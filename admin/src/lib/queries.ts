import "server-only";
import type { AdminScope } from "./admin-scope";
import { callIam } from "./iam-api";

/** 조회 실패를 화면에서 한 번에 다루기 위한 예외. error.tsx 가 메시지를 보여준다 */
export class QueryError extends Error {}

/**
 * 서버 컴포넌트에서 IAM 조회 API 를 부른다. 실패하면 [QueryError] 를 던진다.
 * [returnTo] 는 토큰이 만료되어 다시 로그인한 뒤 돌아올 경로다.
 */
export async function query<T>(path: string, returnTo: string): Promise<T> {
  const result = await callIam<T>(path, {}, returnTo);
  if (!result.ok) throw new QueryError(`${result.message} (${result.code})`);
  return result.data;
}

type SubjectName = { subjectId: number; subjectName: string; subjectType: string };

/** subject ID → 이름. 목록에서 ID 대신 이름을 보여줄 때 쓴다 */
export async function subjectNames(ids: number[], returnTo: string): Promise<Map<number, string>> {
  const unique = [...new Set(ids)];
  if (unique.length === 0) return new Map();
  const names = await query<SubjectName[]>(`/api/v1/subjects/names?ids=${unique.join(",")}`, returnTo);
  return new Map(names.map((n) => [n.subjectId, n.subjectName]));
}

/** 본인의 관리 범위. 화면에서 쓸 수 없는 영역(전체 관리자 전용 API)을 부르지 않으려고 먼저 읽는다 */
export const adminScope = (returnTo: string) => query<AdminScope>("/api/v1/me/admin-scope", returnTo);

/** 표시용 시각 (한국 시각) */
export const formatTime = (iso: string | null | undefined) =>
  iso ? new Date(iso).toLocaleString("ko-KR", { timeZone: "Asia/Seoul", dateStyle: "short", timeStyle: "short" }) : "—";
