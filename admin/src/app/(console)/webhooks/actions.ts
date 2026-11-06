"use server";

import { refresh } from "next/cache";
import { mutate, num, text, type ActionState } from "@/lib/actions";
import { callIam } from "@/lib/iam-api";

const here = "/webhooks";

/** "전체"를 고르면 다른 유형은 보지 않는다 */
function spec(form: FormData) {
  const types = form.getAll("eventTypes").filter((v): v is string => typeof v === "string");
  return { name: text(form, "name"), url: text(form, "url"), eventTypes: types.includes("*") ? ["*"] : types };
}

/** 비밀값은 이 응답에서 한 번만 받으므로 mutate 대신 직접 불러 메시지에 담는다 */
async function withSecret(path: string, body: unknown, done: string, returnTo: string): Promise<ActionState> {
  const result = await callIam<{ secret: string }>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) }, returnTo);
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  return { ok: true, message: `${done}. 서명 비밀값: ${result.data.secret} — 다시 보여주지 않으니 지금 복사해 받는 시스템에 넣으세요` };
}

export async function createWebhook(_: ActionState, form: FormData): Promise<ActionState> {
  return withSecret("/api/v1/webhooks", spec(form), "추가했습니다", here);
}

export async function updateWebhook(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "webhookId");
  return mutate(`/api/v1/webhooks/${id}`, "PUT", spec(form), "저장했습니다", `${here}?edit=${id}`);
}

export async function changeWebhookActive(_: ActionState, form: FormData): Promise<ActionState> {
  const op = text(form, "active") === "true" ? "activate" : "deactivate";
  return mutate(`/api/v1/webhooks/${num(form, "webhookId")}/${op}`, "POST", undefined, op === "activate" ? "켰습니다" : "껐습니다", here);
}

export async function rotateWebhookSecret(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "webhookId");
  return withSecret(`/api/v1/webhooks/${id}/rotate-secret`, undefined, "비밀값을 바꿨습니다", `${here}?id=${id}`);
}

export async function sendWebhookTest(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "webhookId");
  return mutate(`/api/v1/webhooks/${id}/test`, "POST", undefined, "시험 이벤트를 넣었습니다. 잠시 뒤 전달 기록에서 결과를 확인하세요", `${here}?id=${id}`);
}

export async function redeliverWebhook(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/webhook-deliveries/${num(form, "deliveryId")}/redeliver`, "POST", undefined, "다시 보냅니다", `${here}?id=${num(form, "webhookId")}`);
}
