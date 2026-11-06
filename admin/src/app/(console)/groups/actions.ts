"use server";

import { mutate, num, text, type ActionState } from "@/lib/actions";

export async function createGroup(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/groups",
    "POST",
    { groupCode: text(form, "groupCode"), groupName: text(form, "groupName"), groupType: text(form, "groupType"), ruleExpression: text(form, "ruleExpression") },
    "그룹을 만들었습니다",
    "/groups",
  );
}

export async function addGroupMember(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "groupId");
  return mutate(`/api/v1/groups/${id}/members`, "POST", { subjectId: num(form, "subjectId") }, "구성원을 추가했습니다", `/groups/${id}`);
}

export async function removeGroupMember(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "groupId");
  return mutate(`/api/v1/groups/${id}/members/${num(form, "subjectId")}`, "DELETE", undefined, "구성원을 뺐습니다", `/groups/${id}`);
}

export async function createGroupRole(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "groupId");
  return mutate("/api/v1/group-roles", "POST", { groupId: id, roleId: num(form, "roleId"), scopeId: num(form, "scopeId") }, "그룹 역할 규칙을 만들었습니다", `/groups/${id}`);
}

export async function deleteGroupRole(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/group-roles/${num(form, "groupRoleId")}`, "DELETE", undefined, "규칙을 삭제했습니다", `/groups/${num(form, "groupId")}`);
}

export async function updateGroup(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "groupId");
  return mutate(`/api/v1/groups/${id}`, "PUT", { groupName: text(form, "groupName"), ruleExpression: text(form, "ruleExpression") }, "저장했습니다", `/groups/${id}?edit=1`);
}

export async function changeGroupActive(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "groupId");
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/groups/${id}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", `/groups/${id}`);
}
