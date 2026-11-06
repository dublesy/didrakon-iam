"use client";

import { useActionState } from "react";
import { buttonClass } from "@/components/ui";
import { changeAssignmentUntil } from "../actions";

/** 보유 역할 표의 직접 할당 한 줄에서 만료(종료 시각)를 바꾼다. 비우면 기한 없음 */
export function AssignmentUntilForm({ subjectId, assignmentId, current }: { subjectId: string; assignmentId: number; current: string }) {
  const [state, formAction, pending] = useActionState(changeAssignmentUntil, null);
  return (
    <form action={formAction} className="inline-flex flex-wrap items-center gap-2">
      <input type="hidden" name="subjectId" value={subjectId} />
      <input type="hidden" name="assignmentId" value={assignmentId} />
      <input
        name="validUntil"
        type="datetime-local"
        defaultValue={current}
        aria-label="만료"
        className="h-7 rounded-md border border-field-line bg-surface px-2 text-xs text-ink focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-accent"
      />
      <button type="submit" disabled={pending} className={buttonClass.row}>
        {pending ? "처리 중" : "만료 변경"}
      </button>
      {state && (
        <span role={state.ok ? "status" : "alert"} className={`text-xs ${state.ok ? "text-success" : "text-danger"}`}>
          {state.message}
        </span>
      )}
    </form>
  );
}
