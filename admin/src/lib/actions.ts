import "server-only";
import { refresh } from "next/cache";
import { callIam } from "./iam-api";

/** 서버 액션 결과. 폼 아래에 메시지로 보여준다 */
export type ActionState = { ok: boolean; message: string } | null;

/**
 * 서버 액션에서 IAM API 로 변경을 보낸다. 성공하면 화면 데이터를 다시 읽게 한다.
 * [returnTo] 는 토큰이 만료되어 다시 로그인한 뒤 돌아올 경로다.
 */
export async function mutate(
  path: string,
  method: "POST" | "PUT" | "DELETE",
  body: unknown,
  successMessage: string,
  returnTo: string,
): Promise<ActionState> {
  const result = await callIam(path, { method, body: body === undefined ? undefined : JSON.stringify(body) }, returnTo);
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: successMessage };
}

/** 폼 값 읽기. 빈 문자열은 없는 값으로 본다 */
export function text(form: FormData, name: string): string | undefined {
  const value = form.get(name);
  return typeof value === "string" && value.trim() !== "" ? value.trim() : undefined;
}

export function num(form: FormData, name: string): number | undefined {
  const value = text(form, name);
  return value === undefined ? undefined : Number(value);
}

/** 체크박스 */
export const bool = (form: FormData, name: string) => form.get(name) === "on";

/** datetime-local 입력(한국 시각)을 ISO 시각으로 바꾼다 */
export function instant(form: FormData, name: string): string | undefined {
  const value = text(form, name);
  return value === undefined ? undefined : new Date(`${value}:00+09:00`).toISOString();
}
