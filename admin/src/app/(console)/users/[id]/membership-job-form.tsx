"use client";

import { useActionState, useState } from "react";
import { buttonClass } from "@/components/ui";
import type { Membership } from "@/lib/types";
import { updateMembershipJob } from "../actions";

const inputClass =
  "h-7 w-24 rounded-md border border-field-line bg-surface px-2 text-xs text-ink focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent";

/** 소속 표 한 줄에서 직위·직급·조직장 여부를 고친다. from 은 저장 후 돌아갈 화면 (사용자 상세 또는 조직 상세) */
export function MembershipJobForm({ membership, from }: { membership: Membership; from: "user" | "org" }) {
  const [open, setOpen] = useState(false);
  const [state, formAction, pending] = useActionState(updateMembershipJob, null);

  if (!open) {
    return (
      <button type="button" onClick={() => setOpen(true)} className={buttonClass.row}>
        수정
      </button>
    );
  }

  return (
    <form action={formAction} className="inline-flex flex-wrap items-center gap-2">
      <input type="hidden" name="membershipId" value={membership.membershipId} />
      <input type="hidden" name="subjectId" value={membership.subjectId} />
      <input type="hidden" name="orgId" value={membership.orgId} />
      <input type="hidden" name="from" value={from} />
      <input name="jobTitle" maxLength={100} defaultValue={membership.jobTitle ?? ""} placeholder="직위" aria-label="직위" className={inputClass} />
      <input name="jobGrade" maxLength={100} defaultValue={membership.jobGrade ?? ""} placeholder="직급" aria-label="직급" className={inputClass} />
      <label className="inline-flex items-center gap-1 text-xs text-ink-2">
        <input type="checkbox" name="isManager" defaultChecked={membership.isManager} />
        조직 관리자
      </label>
      <button type="submit" disabled={pending} className={buttonClass.row}>
        {pending ? "처리 중" : "저장"}
      </button>
      <button type="button" onClick={() => setOpen(false)} className={buttonClass.row}>
        닫기
      </button>
      {state && (
        <span role={state.ok ? "status" : "alert"} className={`text-xs ${state.ok ? "text-success" : "text-danger"}`}>
          {state.message}
        </span>
      )}
    </form>
  );
}
