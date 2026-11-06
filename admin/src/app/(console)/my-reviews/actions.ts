"use server";

import { mutate, num, text, type ActionState } from "@/lib/actions";

export async function decideMyReview(_: ActionState, form: FormData): Promise<ActionState> {
  const decision = text(form, "decision");
  return mutate(
    `/api/v1/me/access-review-items/${num(form, "itemId")}/decide`,
    "POST",
    { decision, comment: text(form, "comment") },
    decision === "REVOKE" ? "회수했습니다" : "유지했습니다",
    "/my-reviews",
  );
}
