"use server";

import { mutate, num, text, type ActionState } from "@/lib/actions";

const here = "/risk-policies";

/** 신호별 입력 칸을 엔진이 읽는 조건 JSON 으로 모은다. 비운 칸은 엔진 기본값을 쓴다 */
function condition(form: FormData): string {
  const signal = text(form, "signal");
  const value: Record<string, unknown> = { signal };
  if (signal === "UNUSUAL_TIME") {
    value.from = text(form, "from");
    value.to = text(form, "to");
  }
  if (signal === "FAILED_LOGIN_BURST" || signal === "MASS_ACCESS") value.threshold = num(form, "threshold");
  if (signal === "MASS_ACCESS") value.windowSeconds = num(form, "windowSeconds");
  if (signal === "FOREIGN_IP") {
    value.allowedCountries = text(form, "allowedCountries")
      ?.split(",")
      .map((c) => c.trim().toUpperCase())
      .filter(Boolean);
  }
  return JSON.stringify(value);
}

function spec(form: FormData) {
  return { policyName: text(form, "policyName"), conditionExpression: condition(form), riskScore: num(form, "riskScore"), action: text(form, "action") };
}

export async function createRiskPolicy(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate("/api/v1/risk-policies", "POST", { riskType: text(form, "riskType"), ...spec(form) }, "위험 정책을 추가했습니다", here);
}

export async function updateRiskPolicy(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/risk-policies/${num(form, "riskPolicyId")}`, "PUT", spec(form), "저장했습니다", `${here}?edit=${num(form, "riskPolicyId")}`);
}

export async function changeRiskPolicyActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/risk-policies/${num(form, "riskPolicyId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", here);
}
