"use server";

import { bool, mutate, num, text, type ActionState } from "@/lib/actions";

const here = "/break-glass";

const conditions = (form: FormData) => ({
  policyName: text(form, "policyName"),
  maxDurationMinutes: num(form, "maxDurationMinutes"),
  requireReason: bool(form, "requireReason"),
  requireApproval: bool(form, "requireApproval"),
  requireMfa: bool(form, "requireMfa"),
  eligibleGroupId: num(form, "eligibleGroupId"),
});

export async function createBreakGlassPolicy(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/break-glass-policies",
    "POST",
    { ...conditions(form), roleId: num(form, "roleId"), scopeId: num(form, "scopeId") },
    "정책을 만들었습니다",
    here,
  );
}

export async function updateBreakGlassPolicy(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "policyId");
  return mutate(`/api/v1/break-glass-policies/${id}`, "PUT", conditions(form), "저장했습니다", `${here}?edit=${id}`);
}

export async function changeBreakGlassPolicyActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/break-glass-policies/${num(form, "policyId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", here);
}

export async function endBreakGlassSession(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/break-glass-sessions/${num(form, "sessionId")}/end`, "POST", undefined, "비상 접근을 끝냈습니다", here);
}
