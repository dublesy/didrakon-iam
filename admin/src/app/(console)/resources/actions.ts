"use server";

import { refresh } from "next/cache";
import { bool, mutate, num, text, type ActionState } from "@/lib/actions";
import { callIam } from "@/lib/iam-api";

export async function createResource(_: ActionState, form: FormData): Promise<ActionState> {
  const clientId = num(form, "clientId");
  return mutate(
    "/api/v1/resources",
    "POST",
    {
      clientId,
      resourceKey: text(form, "resourceKey"),
      resourceName: text(form, "resourceName"),
      resourceType: text(form, "resourceType"),
      sensitivity: text(form, "sensitivity"),
      parentResourceId: num(form, "parentResourceId"),
      resourcePath: text(form, "resourcePath"),
    },
    "리소스를 만들었습니다",
    `/resources?clientId=${clientId}`,
  );
}

export async function createPermission(_: ActionState, form: FormData): Promise<ActionState> {
  const resourceId = num(form, "resourceId");
  return mutate(
    "/api/v1/permissions",
    "POST",
    {
      permissionCode: text(form, "permissionCode"),
      permissionName: text(form, "permissionName"),
      resourceId,
      action: text(form, "action"),
      effect: text(form, "effect"),
    },
    "권한을 만들었습니다",
    `/resources?clientId=${num(form, "clientId")}&resourceId=${resourceId}`,
  );
}

/** 줄바꿈·쉼표·공백으로 나눈 목록 */
const list = (form: FormData, name: string) => (text(form, name) ?? "").split(/[\s,]+/).filter((v) => v !== "");

type RegisteredClient = { ssoClientId: number; clientId: string; clientSecret: string | null };

/** 비밀값은 이 응답에서 한 번만 받으므로 mutate 대신 직접 불러 메시지에 담는다 */
export async function registerClient(_: ActionState, form: FormData): Promise<ActionState> {
  const result = await callIam<RegisteredClient>(
    "/api/v1/clients",
    {
      method: "POST",
      body: JSON.stringify({
        clientCode: text(form, "clientCode"),
        clientName: text(form, "clientName"),
        clientType: text(form, "clientType"),
        redirectUris: list(form, "redirectUris"),
        postLogoutRedirectUris: list(form, "postLogoutRedirectUris"),
        scopes: list(form, "scopes"),
        confidential: bool(form, "confidential"),
        requireMfa: bool(form, "requireMfa"),
        backchannelLogoutUri: text(form, "backchannelLogoutUri"),
        supabaseRoleClaim: bool(form, "supabaseRoleClaim"),
        homeUrl: text(form, "homeUrl"),
      }),
    },
    "/resources",
  );
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  const { clientId, clientSecret } = result.data;
  const secret = clientSecret
    ? `client_secret: ${clientSecret} — 비밀값은 다시 보여주지 않으니 지금 안전한 곳에 보관하세요`
    : "공개 클라이언트라 비밀값이 없습니다";
  return { ok: true, message: `등록했습니다. client_id: ${clientId} · ${secret}` };
}

/** 수정 후 돌아올 화면. 선택한 클라이언트·리소스를 유지한다 */
function page(form: FormData, extra = ""): string {
  const resourceId = num(form, "resourceId");
  return `/resources?clientId=${num(form, "clientId")}${resourceId === undefined ? "" : `&resourceId=${resourceId}`}${extra}`;
}

const activeOp = (form: FormData) => (text(form, "active") === "true" ? "activate" : "deactivate");

/** 폼에 없는 칸(관리 콘솔 클라이언트의 로그인 설정)은 보내지 않아 그대로 둔다 */
const listIfPresent = (form: FormData, name: string) => (form.has(name) ? list(form, name) : undefined);

export async function updateClient(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "clientId");
  return mutate(
    `/api/v1/clients/${id}`,
    "PUT",
    {
      clientName: text(form, "clientName"),
      requireMfa: bool(form, "requireMfa"),
      backchannelLogoutUri: text(form, "backchannelLogoutUri"),
      supabaseRoleClaim: bool(form, "supabaseRoleClaim"),
      homeUrl: text(form, "homeUrl"),
      redirectUris: listIfPresent(form, "redirectUris"),
      postLogoutRedirectUris: listIfPresent(form, "postLogoutRedirectUris"),
      scopes: listIfPresent(form, "scopes"),
    },
    "저장했습니다",
    page(form, `&editClient=${id}`),
  );
}

/** 새 비밀값은 이 응답에서 한 번만 받으므로 mutate 대신 직접 불러 메시지에 담는다 */
export async function rotateClientSecret(_: ActionState, form: FormData): Promise<ActionState> {
  const result = await callIam<{ clientSecret: string }>(`/api/v1/clients/${num(form, "clientId")}/rotate-secret`, { method: "POST" }, page(form));
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: `비밀값을 다시 발급했습니다. client_secret: ${result.data.clientSecret} — 다시 보여주지 않으니 지금 복사해 연동 시스템에 넣으세요` };
}

export async function changeClientActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = activeOp(form);
  return mutate(`/api/v1/clients/${num(form, "clientId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", page(form));
}

export async function updateResource(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "resourceId");
  return mutate(
    `/api/v1/resources/${id}`,
    "PUT",
    {
      resourceName: text(form, "resourceName"),
      resourceType: text(form, "resourceType"),
      resourcePath: text(form, "resourcePath"),
      sensitivity: text(form, "sensitivity"),
    },
    "저장했습니다",
    page(form, `&editResource=${id}`),
  );
}

export async function changeResourceActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = activeOp(form);
  return mutate(`/api/v1/resources/${num(form, "resourceId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", page(form));
}

export async function updatePermission(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "permissionId");
  return mutate(`/api/v1/permissions/${id}`, "PUT", { name: text(form, "permissionName") }, "저장했습니다", page(form, `&editPermission=${id}`));
}

export async function changePermissionActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = activeOp(form);
  return mutate(`/api/v1/permissions/${num(form, "permissionId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", page(form));
}
