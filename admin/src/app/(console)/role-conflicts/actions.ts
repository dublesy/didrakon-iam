"use server";

import { instant, mutate, num, text, type ActionState } from "@/lib/actions";

export async function defineConflict(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/role-conflicts",
    "POST",
    { roleId1: num(form, "roleId1"), roleId2: num(form, "roleId2"), severity: text(form, "severity"), description: text(form, "description") },
    "충돌 규칙을 만들었습니다",
    "/role-conflicts",
  );
}

export async function grantConflictException(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    `/api/v1/role-conflicts/${num(form, "conflictId")}/exceptions`,
    "POST",
    { subjectId: num(form, "subjectId"), reason: text(form, "reason"), validUntil: instant(form, "validUntil") },
    "예외를 허용했습니다",
    "/role-conflicts",
  );
}

export async function changeConflictActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/role-conflicts/${num(form, "conflictId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", "/role-conflicts");
}

export async function endConflictException(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/role-conflict-exceptions/${num(form, "exceptionId")}`, "DELETE", undefined, "예외를 끝냈습니다", "/role-conflicts");
}

/** 심각도·설명만 바꾼다. 역할 쌍을 바꾸려면 새 규칙을 만들고 이 규칙을 끈다 */
export async function updateConflict(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    `/api/v1/role-conflicts/${num(form, "conflictId")}`,
    "PUT",
    { severity: text(form, "severity"), description: text(form, "description") ?? null },
    "저장했습니다",
    "/role-conflicts",
  );
}
