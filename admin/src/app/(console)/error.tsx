"use client";

/** 조회 실패(권한 없음·MFA 필요 등)를 페이지 안에서 보여준다. 스택이나 내부 메시지는 내보내지 않는다 */
export default function ErrorPage({ error, reset }: { error: Error & { digest?: string }; reset: () => void }) {
  const mfa = error.message.includes("MFA_REQUIRED");
  return (
    <div role="alert" className="space-y-3 rounded-xl bg-danger-soft p-5 text-danger">
      <p className="font-medium">화면을 불러오지 못했습니다</p>
      <p className="text-ink-2">
        {mfa
          ? "관리 기능은 2단계 인증을 거친 로그인에서만 쓸 수 있습니다. 2단계 인증 메뉴에서 등록한 뒤 다시 로그인하세요."
          : "권한이 없거나 서버가 응답하지 않았습니다. 잠시 뒤 다시 시도하고, 계속되면 관리자에게 아래 오류 번호를 알려 주세요."}
      </p>
      {error.digest && !mfa && (
        <p className="text-xs text-ink-3">
          오류 번호 <span className="font-mono">{error.digest}</span>
        </p>
      )}
      <button
        type="button"
        onClick={reset}
        className="h-9 rounded-lg border border-line-strong bg-surface px-3 font-medium text-ink transition-colors hover:bg-panel"
      >
        다시 시도
      </button>
    </div>
  );
}
