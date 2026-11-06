"use server";

import { bool, mutate, num, text, type ActionState } from "@/lib/actions";

export async function createOrganization(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(
    "/api/v1/organizations",
    "POST",
    { orgCode: text(form, "orgCode"), orgName: text(form, "orgName"), orgType: text(form, "orgType"), parentOrgId: num(form, "parentOrgId") },
    "조직을 만들었습니다",
    "/organizations",
  );
}

export async function moveOrganization(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "orgId");
  return mutate(`/api/v1/organizations/${id}/move`, "POST", { newParentOrgId: num(form, "newParentOrgId") }, "조직을 옮겼습니다", `/organizations/${id}`);
}

export async function createOrganizationRole(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "orgId");
  return mutate(
    "/api/v1/organization-roles",
    "POST",
    { orgId: id, roleId: num(form, "roleId"), scopeId: num(form, "scopeId"), applyToDescendants: bool(form, "applyToDescendants") },
    "조직 역할 규칙을 만들었습니다",
    `/organizations/${id}`,
  );
}

export async function deactivateOrganizationRole(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/organization-roles/${num(form, "orgRoleId")}`, "DELETE", undefined, "규칙을 비활성화했습니다", `/organizations/${num(form, "orgId")}`);
}

export async function updateOrganization(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "orgId");
  return mutate(`/api/v1/organizations/${id}`, "PUT", { orgName: text(form, "orgName"), orgType: text(form, "orgType") }, "저장했습니다", `/organizations/${id}?edit=1`);
}

export async function changeOrganizationActive(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "orgId");
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/organizations/${id}/${op}`, "POST", undefined, op === "activate" ? "다시 열었습니다" : "닫았습니다", `/organizations/${id}`);
}
