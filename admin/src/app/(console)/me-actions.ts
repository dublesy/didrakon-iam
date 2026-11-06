"use server";

import { mutate, text, type ActionState } from "@/lib/actions";

export async function changeOwnPassword(_: ActionState, form: FormData): Promise<ActionState> {
  const next = text(form, "newPassword");
  if (next !== text(form, "confirmPassword")) return { ok: false, message: "두 새 비밀번호가 다릅니다" };
  return mutate("/api/v1/me/password", "POST", { currentPassword: text(form, "currentPassword"), newPassword: next }, "비밀번호를 바꿨습니다. 모든 기기에서 로그아웃되니 새 비밀번호로 다시 로그인하세요", "/");
}
