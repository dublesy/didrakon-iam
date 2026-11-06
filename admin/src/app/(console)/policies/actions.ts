"use server";

import { instant, mutate, num, text, type ActionState } from "@/lib/actions";

const TARGET_FIELDS: Record<string, string> = { role: "roleId", resource: "resourceId", permission: "permissionId" };

export async function createPolicy(_: ActionState, form: FormData): Promise<ActionState> {
  const field = TARGET_FIELDS[text(form, "targetKind") ?? ""];
  const targetId = num(form, "targetId");
  if (!field || targetId === undefined) return { ok: false, message: "대상을 고르세요" };
  return mutate(
    "/api/v1/policies",
    "POST",
    {
      policyCode: text(form, "policyCode"),
      policyName: text(form, "policyName"),
      policyType: text(form, "policyType"),
      effect: text(form, "effect"),
      priority: num(form, "priority") ?? 0,
      targets: [{ [field]: targetId }],
    },
    "정책을 만들었습니다. 상세에서 규칙 버전을 만들고 활성화하세요",
    "/policies",
  );
}

type RuleInput = { ruleGroup: number; attributeSource: string; attributeName: string; operator: string; attributeValue: string | null; ruleOrder: number };

/** 화면의 규칙 행(JSON)을 API 요청 형태로 바꾼다. 형식이 틀리면 undefined */
function parseRules(raw: string | undefined): RuleInput[] | undefined {
  if (raw === undefined) return undefined;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return undefined;
  }
  if (!Array.isArray(parsed)) return undefined;
  const rules: RuleInput[] = [];
  for (const [i, row] of parsed.entries()) {
    if (typeof row !== "object" || row === null) return undefined;
    const r = row as Record<string, unknown>;
    const value = typeof r.attributeValue === "string" ? r.attributeValue.trim() : "";
    rules.push({
      ruleGroup: Number(r.ruleGroup) || 0,
      attributeSource: String(r.attributeSource ?? ""),
      attributeName: String(r.attributeName ?? "").trim(),
      operator: String(r.operator ?? ""),
      attributeValue: value === "" ? null : value,
      ruleOrder: i,
    });
  }
  return rules;
}

export async function createVersion(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "policyId");
  const rules = parseRules(text(form, "rules"));
  if (!rules) return { ok: false, message: "규칙 형식이 올바르지 않습니다" };
  return mutate(
    `/api/v1/policies/${id}/versions`,
    "POST",
    { rules, changeReason: text(form, "changeReason") },
    "새 버전(DRAFT)을 만들었습니다. 확인 후 활성화하세요",
    `/policies/${id}`,
  );
}

export async function activateVersion(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/policy-versions/${num(form, "versionId")}/activate`, "POST", undefined, "활성화했습니다", `/policies/${num(form, "policyId")}`);
}

export async function addPolicyException(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "policyId");
  const subjectId = num(form, "subjectId");
  const resourceId = num(form, "resourceId");
  if (subjectId === undefined && resourceId === undefined) return { ok: false, message: "대상자나 리소스 중 하나는 넣으세요" };
  return mutate(
    `/api/v1/policies/${id}/exceptions`,
    "POST",
    { subjectId, resourceId, reason: text(form, "reason"), validUntil: instant(form, "validUntil") },
    "예외를 추가했습니다",
    `/policies/${id}`,
  );
}

export async function updatePolicy(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "policyId");
  return mutate(`/api/v1/policies/${id}`, "PUT", { policyName: text(form, "policyName"), priority: num(form, "priority") ?? 0 }, "저장했습니다", `/policies/${id}`);
}

export async function changePolicyActive(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "policyId");
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/policies/${id}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", `/policies/${id}`);
}

export async function endPolicyException(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/policy-exceptions/${num(form, "exceptionId")}`, "DELETE", undefined, "예외를 끝냈습니다", `/policies/${num(form, "policyId")}`);
}

type TargetInput = { permissionId?: number; resourceId?: number; roleId?: number };

/** 화면이 넘긴 지금 대상 묶음(JSON). 형식이 틀리면 undefined */
function parseTargets(raw: string | undefined): TargetInput[] | undefined {
  if (raw === undefined) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw);
    return Array.isArray(parsed) ? (parsed as TargetInput[]) : undefined;
  } catch {
    return undefined;
  }
}

/** 대상 묶음 전체를 보낸다 (PUT 은 보낸 것으로 바꾼다) */
function replaceTargets(id: number | undefined, targets: TargetInput[], message: string): Promise<ActionState> {
  return mutate(`/api/v1/policies/${id}/targets`, "PUT", { targets }, message, `/policies/${id}`);
}

export async function addPolicyTarget(_: ActionState, form: FormData): Promise<ActionState> {
  const field = TARGET_FIELDS[text(form, "targetKind") ?? ""];
  const targetId = num(form, "targetId");
  const current = parseTargets(text(form, "targets"));
  if (!field || targetId === undefined) return { ok: false, message: "대상을 고르세요" };
  if (!current) return { ok: false, message: "대상 형식이 올바르지 않습니다" };
  return replaceTargets(num(form, "policyId"), [...current, { [field]: targetId }], "대상을 더했습니다. 다음 판정부터 적용됩니다");
}

export async function removePolicyTarget(_: ActionState, form: FormData): Promise<ActionState> {
  const remaining = parseTargets(text(form, "targets"));
  if (!remaining) return { ok: false, message: "대상 형식이 올바르지 않습니다" };
  return replaceTargets(num(form, "policyId"), remaining, "대상을 뺐습니다. 다음 판정부터 적용됩니다");
}
