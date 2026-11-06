"use server";

import { bool, instant, mutate, num, text, type ActionState } from "@/lib/actions";

const here = "/access-reviews";

/** 범위 유형에 맞는 대상만 보낸다 (조직·역할 선택란은 늘 보이므로) */
export async function createReview(_: ActionState, form: FormData): Promise<ActionState> {
  const scopeType = text(form, "scopeType");
  const sources = form.getAll("sources").filter((v): v is string => typeof v === "string");
  return mutate(
    "/api/v1/access-reviews",
    "POST",
    {
      name: text(form, "name"),
      scopeType,
      scopeOrgId: scopeType === "ORGANIZATION" ? num(form, "scopeOrgId") : undefined,
      scopeRoleId: scopeType === "ROLE" ? num(form, "scopeRoleId") : undefined,
      includeDescendants: bool(form, "includeDescendants"),
      privilegedOnly: bool(form, "privilegedOnly"),
      sources,
      dueAt: instant(form, "dueAt"),
      onOverdue: text(form, "onOverdue"),
      escalationDays: num(form, "escalationDays"),
    },
    "시작했습니다. 검토자에게 할 일이 생겼습니다",
    here,
  );
}

export async function decideReviewItem(_: ActionState, form: FormData): Promise<ActionState> {
  const decision = text(form, "decision");
  return mutate(
    `/api/v1/access-review-items/${num(form, "itemId")}/decide`,
    "POST",
    { decision, comment: text(form, "comment") },
    decision === "REVOKE" ? "회수했습니다" : "유지했습니다",
    `${here}?id=${num(form, "campaignId")}`,
  );
}

export async function closeReview(_: ActionState, form: FormData): Promise<ActionState> {
  const id = num(form, "campaignId");
  return mutate(`/api/v1/access-reviews/${id}/close`, "POST", undefined, "마감했습니다", `${here}?id=${id}`);
}
