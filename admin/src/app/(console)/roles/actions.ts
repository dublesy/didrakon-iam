"use server";

import { bool, mutate, num, text, type ActionState } from "@/lib/actions";

export async function createRole(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/roles",
    "POST",
    {
      roleCode: text(form, "roleCode"),
      roleName: text(form, "roleName"),
      roleType: text(form, "roleType"),
      isSensitive: bool(form, "isSensitive"),
      isPrivileged: bool(form, "isPrivileged"),
      priority: num(form, "priority") ?? 0,
    },
    "역할을 만들었습니다",
    "/roles",
  );
}

export async function updateRole(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "roleId");
  return mutate(
    `/api/v1/roles/${id}`,
    "PUT",
    {
      roleName: text(form, "roleName"),
      roleType: text(form, "roleType"),
      priority: num(form, "priority") ?? 0,
      isSensitive: bool(form, "isSensitive"),
      isPrivileged: bool(form, "isPrivileged"),
    },
    "저장했습니다",
    `/roles/${id}?edit=1`,
  );
}

export async function changeRoleActive(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "roleId");
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/roles/${id}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", `/roles/${id}`);
}

export async function grantPermission(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "roleId");
  return mutate(
    `/api/v1/roles/${id}/permissions`,
    "POST",
    { permissionId: num(form, "permissionId"), scopeId: num(form, "scopeId") },
    "권한을 추가했습니다",
    `/roles/${id}`,
  );
}

export async function removeRolePermission(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/role-permissions/${num(form, "rolePermissionId")}`, "DELETE", undefined, "권한을 뺐습니다", `/roles/${num(form, "roleId")}`);
}
