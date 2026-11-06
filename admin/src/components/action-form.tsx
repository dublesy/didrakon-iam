"use client";

import { useActionState, useEffect, useRef, type ReactNode } from "react";
import { buttonClass } from "@/components/ui";
import type { ActionState } from "@/lib/actions";

type Props = {
  action: (state: ActionState, form: FormData) => Promise<ActionState>;
  submitLabel: string;
  children?: ReactNode;
  /** 성공하면 입력값을 비운다 (생성 폼) */
  resetOnSuccess?: boolean;
  /** 되돌리기 어려운 작업은 확인을 받는다 */
  confirmMessage?: string;
  variant?: "primary" | "danger" | "subtle";
  className?: string;
};

const buttonStyles = { primary: buttonClass.primary, danger: buttonClass.danger, subtle: buttonClass.secondary };

/** 서버 액션 폼. 처리 중 버튼을 막고, 결과 메시지를 버튼 옆에 보여준다 */
export function ActionForm({ action, submitLabel, children, resetOnSuccess, confirmMessage, variant = "primary", className = "" }: Props) {
  const [state, formAction, pending] = useActionState(action, null);
  const formRef = useRef<HTMLFormElement>(null);

  useEffect(() => {
    if (state?.ok && resetOnSuccess) formRef.current?.reset();
  }, [state, resetOnSuccess]);

  return (
    <form
      ref={formRef}
      action={formAction}
      className={className}
      onSubmit={(e) => {
        if (confirmMessage && !window.confirm(confirmMessage)) e.preventDefault();
      }}
    >
      {children}
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button
          type="submit"
          disabled={pending}
          className={buttonStyles[variant]}
        >
          {pending ? "처리 중" : submitLabel}
        </button>
        {state && (
          <p role={state.ok ? "status" : "alert"} className={state.ok ? "text-success" : "text-danger"}>
            {state.message}
          </p>
        )}
      </div>
    </form>
  );
}

/** 표 안의 한 줄짜리 작업 버튼 (회수·종료 등). 숨은 값은 hidden 으로 넘긴다. 되돌리기 쉬운 작업은 tone="neutral" */
export function RowAction({ action, label, hidden, confirmMessage, tone = "danger" }: {
  action: Props["action"];
  label: string;
  hidden: Record<string, string | number>;
  confirmMessage?: string;
  tone?: "danger" | "neutral";
}) {
  const [state, formAction, pending] = useActionState(action, null);
  return (
    <form
      action={formAction}
      className="inline-flex items-center gap-2"
      onSubmit={(e) => {
        if (confirmMessage && !window.confirm(confirmMessage)) e.preventDefault();
      }}
    >
      {Object.entries(hidden).map(([k, v]) => (
        <input key={k} type="hidden" name={k} value={v} />
      ))}
      <button
        type="submit"
        disabled={pending}
        className={tone === "danger" ? buttonClass.rowDanger : buttonClass.row}
      >
        {pending ? "처리 중" : label}
      </button>
      {state && !state.ok && (
        <span role="alert" className="text-xs text-danger">
          {state.message}
        </span>
      )}
    </form>
  );
}
