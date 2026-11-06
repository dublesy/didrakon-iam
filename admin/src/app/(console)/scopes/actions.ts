"use server";

import { bool, mutate, num, text, type ActionState } from "@/lib/actions";

export async function createScope(_: ActionState, form: FormData): Promise<ActionState> {
  const scopeType = text(form, "scopeType");
  return mutate(
    "/api/v1/scopes",
    "POST",
    {
      scopeCode: text(form, "scopeCode"),
      scopeName: text(form, "scopeName"),
      scopeType,
      // 유형에 맞는 대상만 보낸다
      orgId: scopeType === "ORGANIZATION" ? num(form, "orgId") : undefined,
      resourceId: scopeType === "RESOURCE" ? num(form, "resourceId") : undefined,
      includeDescendants: bool(form, "includeDescendants"),
    },
    "범위를 만들었습니다",
    "/scopes",
  );
}

export async function updateScope(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "scopeId");
  return mutate(
    `/api/v1/scopes/${id}`,
    "PUT",
    { scopeName: text(form, "scopeName"), includeDescendants: bool(form, "includeDescendants") },
    "저장했습니다",
    `/scopes?edit=${id}`,
  );
}

export async function changeScopeActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/scopes/${num(form, "scopeId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", "/scopes");
}
