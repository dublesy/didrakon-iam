"use client";

import { useActionState, useState } from "react";
import { buttonClass, Field, Input } from "@/components/ui";
import { mfaAction, type MfaState } from "./actions";

const initial: MfaState = { step: "start" };

/** 비밀값을 4자씩 끊어 인증 앱에 직접 입력하기 쉽게 보여준다 */
const grouped = (secret: string) => secret.match(/.{1,4}/g)?.join(" ") ?? secret;

const primary = buttonClass.primary;

/** [hasMethods] 면 이미 등록한 앱이 있으므로 "추가 등록"으로 보여준다 (휴대폰 교체 등) */
export function MfaEnrollment({ hasMethods }: { hasMethods: boolean }) {
  const [state, action, pending] = useActionState(mfaAction, initial);
  // 등록을 마치면 목록이 새로 고쳐져 hasMethods 가 바뀐다. 안내 문구는 화면을 연 시점 기준으로 고른다
  const [hadMethods] = useState(hasMethods);

  if (state.step === "done") {
    return (
      <div role="status" className="space-y-3 rounded-xl bg-success-soft p-5 text-success">
        <p className="font-medium">등록을 마쳤습니다</p>
        <p className="text-ink-2">
          {hadMethods
            ? "이제 등록한 어느 앱의 코드로도 로그인할 수 있습니다. 쓰지 않는 앱은 위 목록에서 삭제하세요."
            : "다음 로그인부터 인증 앱 코드를 함께 입력합니다. 관리 기능을 쓰려면 로그아웃한 뒤 다시 로그인하세요."}
        </p>
        {!hadMethods && (
          <form action="/auth/logout" method="post">
            <button type="submit" className={primary}>
              로그아웃
            </button>
          </form>
        )}
      </div>
    );
  }

  if (state.step === "start") {
    return (
      <form action={action} className="space-y-3">
        {state.error && <p role="alert" className="text-danger">{state.error}</p>}
        <button type="submit" name="intent" value="start" disabled={pending} className={primary}>
          {pending ? "처리 중" : hasMethods ? "다른 인증 앱 추가" : "인증 앱 등록 시작"}
        </button>
      </form>
    );
  }

  return (
    <form action={action} className="rounded-xl border border-line bg-surface p-5">
      <div className="flex flex-wrap gap-6">
        {/* 서버가 만든 SVG 라 그대로 넣는다 */}
        <div className="size-40 shrink-0 rounded-lg border border-line p-3 [&>svg]:size-full" role="img" aria-label="인증 앱 등록 QR 코드" dangerouslySetInnerHTML={{ __html: state.qrSvg }} />
        <div className="min-w-0 flex-1 space-y-4">
          <div>
            <p className="font-medium text-ink">1. 인증 앱으로 QR 코드를 찍으세요</p>
            <p className="mt-1 text-ink-3">찍을 수 없으면 &lsquo;키 직접 입력&rsquo;에 아래 키를 넣으세요. 이 화면을 벗어나면 키를 다시 볼 수 없습니다.</p>
            <code className="mt-2 block break-all rounded-lg bg-panel px-3 py-2 font-mono tracking-wider text-ink">{grouped(state.secret)}</code>
            <a href={state.otpauthUri} className="mt-1 inline-block text-xs text-accent hover:underline">
              이 기기에 인증 앱이 있으면 여기를 누르세요
            </a>
          </div>
          <div>
            <p className="mb-2 font-medium text-ink">2. 앱에 표시된 코드를 입력하세요</p>
            <Field label="6자리 코드">
              <Input name="code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} required className="w-36 font-mono tracking-widest" />
            </Field>
          </div>
          {state.error && <p role="alert" className="text-danger">{state.error}</p>}
          <button type="submit" name="intent" value="confirm" disabled={pending} className={primary}>
            {pending ? "처리 중" : "확인"}
          </button>
        </div>
      </div>
    </form>
  );
}
