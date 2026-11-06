"use server";

import { mutate, num, text, type ActionState } from "@/lib/actions";

export async function approveRequest(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/access-requests/${num(form, "requestId")}/approve`, "POST", { comment: text(form, "comment") }, "승인했습니다", "/approvals");
}

export async function rejectRequest(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/access-requests/${num(form, "requestId")}/reject`, "POST", { comment: text(form, "comment") }, "반려했습니다", "/approvals");
}
