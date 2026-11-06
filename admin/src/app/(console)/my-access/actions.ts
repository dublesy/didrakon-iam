"use server";

import { refresh } from "next/cache";
import { instant, mutate, num, text, type ActionState } from "@/lib/actions";
import { callIam } from "@/lib/iam-api";

const here = "/my-access";

const HOUR = 60 * 60 * 1000;

export async function requestAccess(_: ActionState, form: FormData): Promise<ActionState> {
  const hours = num(form, "hours");
  if (!hours || hours <= 0) return { ok: false, message: "사용 시간을 시간 단위로 넣으세요" };
  const start = instant(form, "start") ?? new Date().toISOString();
  const end = new Date(new Date(start).getTime() + hours * HOUR).toISOString();
  return mutate(
    "/api/v1/me/access-requests",
    "POST",
    { roleId: num(form, "roleId"), scopeId: num(form, "scopeId"), reason: text(form, "reason"), requestedStart: start, requestedEnd: end },
    "요청했습니다. 승인되면 요청 기간 동안 역할이 생깁니다",
    here,
  );
}

export async function cancelRequest(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/me/access-requests/${num(form, "requestId")}/cancel`, "POST", undefined, "요청을 취소했습니다", here);
}

/** 대리인은 사번으로 찾는다 */
export async function delegateRole(_: ActionState, form: FormData): Promise<ActionState> {
  const [roleId, scopeId] = (text(form, "roleScope") ?? "").split(":").map(Number);
  const empNo = text(form, "empNo");
  if (!roleId || !scopeId) return { ok: false, message: "위임할 역할을 고르세요" };
  if (!empNo) return { ok: false, message: "대리인 사번을 넣으세요" };
  const person = await callIam<{ subjectId: number; name: string }>(`/api/v1/me/people?empNo=${encodeURIComponent(empNo)}`, {}, here);
  if (!person.ok) return { ok: false, message: `사번 ${empNo} 인 사용 중인 사용자를 찾지 못했습니다. 사번을 확인하세요` };
  return mutate(
    "/api/v1/me/delegations",
    "POST",
    {
      delegateId: person.data.subjectId,
      roleId,
      scopeId,
      startTime: instant(form, "start") ?? new Date().toISOString(),
      endTime: instant(form, "end"),
      reason: text(form, "reason"),
    },
    `${person.data.name} 님에게 위임했습니다`,
    here,
  );
}

export async function endMyDelegation(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/me/delegations/${num(form, "delegationId")}`, "DELETE", undefined, "위임을 거뒀습니다", here);
}

type Activation = { sessionId: number | null; endTime: string | null; pendingRequestId: number | null };

export async function activateBreakGlass(_: ActionState, form: FormData): Promise<ActionState> {
  const result = await callIam<Activation>(
    "/api/v1/me/break-glass",
    { method: "POST", body: JSON.stringify({ policyId: num(form, "policyId"), reason: text(form, "reason") }) },
    here,
  );
  if (!result.ok) {
    // MFA 가 필요한 정책인데 비밀번호로만 로그인한 경우: 무엇을 해야 하는지 함께 알려 준다
    const mfa = result.message.includes("MFA");
    return { ok: false, message: mfa ? `${result.message}. 로그아웃한 뒤 인증 앱이나 패스키로 다시 로그인하세요` : result.message };
  }
  refresh();
  if (result.data.pendingRequestId !== null) return { ok: true, message: "승인이 필요한 정책이라 요청을 올렸습니다. 승인되면 바로 시작됩니다" };
  return { ok: true, message: "비상 접근을 시작했습니다. 일이 끝나면 바로 끝내세요" };
}

export async function endMyBreakGlass(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/me/break-glass/${num(form, "sessionId")}/end`, "POST", undefined, "비상 접근을 끝냈습니다", here);
}
