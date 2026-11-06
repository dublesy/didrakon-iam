"use server";

import { mutate, num, type ActionState } from "@/lib/actions";

export async function revokeDelegation(_: ActionState, form: FormData): Promise<ActionState> {
  return mutate(`/api/v1/delegations/${num(form, "delegationId")}/revoke`, "POST", { reason: "관리자 회수" }, "위임을 회수했습니다", "/delegations");
}
