"use server";

import { refresh } from "next/cache";
import { bool, instant, mutate, num, text, type ActionState } from "@/lib/actions";
import { callIam } from "@/lib/iam-api";

export async function createUser(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/users",
    "POST",
    {
      empNo: text(form, "empNo"),
      name: text(form, "name"),
      email: text(form, "email"),
      phone: text(form, "phone"),
      hireDate: text(form, "hireDate"),
      loginId: text(form, "loginId"),
      password: text(form, "password"),
      userKind: text(form, "userKind"),
      primaryOrgId: num(form, "primaryOrgId"),
    },
    "사용자를 만들었습니다",
    "/users",
  );
}

export async function resetPassword(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/users/${id}/password`, "POST", { password: text(form, "password") }, "비밀번호를 초기화했습니다. 다음 로그인에서 본인이 바꿔야 합니다", `/users/${id}`);
}

/** 로그인 실패로 잠긴 계정을 푼다. 비밀번호는 그대로 */
export async function unlockUser(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/users/${id}/unlock`, "POST", undefined, "잠금을 해제했습니다", `/users/${id}`);
}

export async function addMembership(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(
    "/api/v1/memberships",
    "POST",
    {
      subjectId: id,
      orgId: num(form, "orgId"),
      membershipType: text(form, "membershipType"),
      jobTitle: text(form, "jobTitle"),
      jobGrade: text(form, "jobGrade"),
      isManager: bool(form, "isManager"),
    },
    "소속을 추가했습니다",
    `/users/${id}`,
  );
}

export async function transferPrimary(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(
    `/api/v1/subjects/${id}/primary-membership`,
    "POST",
    { newOrgId: num(form, "newOrgId"), jobTitle: text(form, "jobTitle"), jobGrade: text(form, "jobGrade"), isManager: bool(form, "isManager") },
    "주 소속을 옮겼습니다. 법인이 바뀌었으면 권한이 정리됩니다",
    `/users/${id}`,
  );
}

export async function leaveMembership(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/memberships/${num(form, "membershipId")}`, "DELETE", undefined, "소속을 종료했습니다", `/users/${num(form, "subjectId")}`);
}

export async function assignRole(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(
    "/api/v1/assignments",
    "POST",
    { subjectId: id, roleId: num(form, "roleId"), scopeId: num(form, "scopeId"), validUntil: instant(form, "validUntil"), reason: text(form, "reason") },
    "역할을 부여했습니다",
    `/users/${id}`,
  );
}

export async function revokeAssignment(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/assignments/${num(form, "assignmentId")}`, "DELETE", undefined, "회수했습니다", `/users/${num(form, "subjectId")}`);
}

/** 직접 할당의 만료(종료 시각) 변경. 비우면 기한 없음 */
export async function changeAssignmentUntil(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    `/api/v1/assignments/${num(form, "assignmentId")}`,
    "PUT",
    { validUntil: instant(form, "validUntil") ?? null, reason: text(form, "reason") },
    "만료를 바꿨습니다",
    `/users/${num(form, "subjectId")}`,
  );
}

export async function revokeSession(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/sessions/${num(form, "sessionId")}`, "DELETE", undefined, "세션을 종료했습니다", `/users/${num(form, "subjectId")}`);
}

export async function revokeAllSessions(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/subjects/${id}/sessions`, "DELETE", undefined, "모든 세션을 끊었습니다", `/users/${id}`);
}

/** 로그인 계정이 없는 사용자에게 LOCAL 계정을 만든다. 첫 비밀번호는 다음 로그인에서 본인이 바꿔야 한다 */
export async function createLoginAccount(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(
    `/api/v1/users/${id}/login-account`,
    "POST",
    { loginId: text(form, "loginId"), password: text(form, "password") },
    "로그인 계정을 만들었습니다. 첫 로그인에서 본인이 비밀번호를 바꿔야 합니다",
    `/users/${id}`,
  );
}

/** 인증 앱 초기화 (기기 분실) */
export async function removeMfaMethod(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/subjects/${id}/mfa/${num(form, "methodId")}`, "DELETE", undefined, "인증 앱을 지웠습니다", `/users/${id}`);
}

export async function removePasskey(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  const credentialId = encodeURIComponent(text(form, "credentialId") ?? "");
  return mutate(`/api/v1/subjects/${id}/mfa/passkeys/${credentialId}`, "DELETE", undefined, "패스키를 지웠습니다", `/users/${id}`);
}

/** 키 원문은 이 응답에서 한 번만 받으므로 mutate 대신 직접 불러 메시지에 담는다 */
export async function issueApiKey(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  const result = await callIam<{ rawKey: string }>(
    `/api/v1/subjects/${id}/api-keys`,
    { method: "POST", body: JSON.stringify({ keyName: text(form, "keyName"), expireAt: instant(form, "expireAt") }) },
    `/users/${id}`,
  );
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: `발급했습니다. API 키: ${result.data.rawKey} — 다시 보여주지 않으니 지금 복사해 쓸 곳에 넣으세요` };
}

export async function revokeApiKey(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/api-keys/${num(form, "apiKeyId")}`, "DELETE", undefined, "폐기했습니다", `/users/${num(form, "subjectId")}`);
}

export async function updateUser(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(
    `/api/v1/users/${id}`,
    "PUT",
    { name: text(form, "name"), email: text(form, "email"), phone: text(form, "phone"), hireDate: text(form, "hireDate") },
    "저장했습니다",
    `/users/${id}?edit=1`,
  );
}

export async function changeUserActive(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/users/${id}/${op}`, "POST", undefined, op === "activate" ? "다시 사용합니다" : "사용 중지했습니다", `/users/${id}`);
}

/** 퇴사 처리. 되돌릴 수 없다 */
export async function retireUser(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/users/${id}/retire`, "POST", { retireDate: text(form, "retireDate") }, "처리했습니다", `/users/${id}`);
}

export async function cancelRetire(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "subjectId");
  return mutate(`/api/v1/users/${id}/retire`, "DELETE", undefined, "퇴사 예약을 취소했습니다", `/users/${id}`);
}

/** 소속의 직위·직급·조직장 여부만 바꾼다 (조직·유형·기간은 그대로). 조직 화면에서 고치면 그 화면으로 돌아간다 */
export async function updateMembershipJob(_: ActionState, form: FormData): Promise<ActionState> {
  const returnTo = text(form, "from") === "org" ? `/organizations/${num(form, "orgId")}` : `/users/${num(form, "subjectId")}`;
  return mutate(
    `/api/v1/memberships/${num(form, "membershipId")}`,
    "PUT",
    { jobTitle: text(form, "jobTitle") ?? null, jobGrade: text(form, "jobGrade") ?? null, isManager: bool(form, "isManager") },
    "저장했습니다",
    returnTo,
  );
}
