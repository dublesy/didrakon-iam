"use client";

import { useState } from "react";
import { Field, Input, Options, Select } from "@/components/ui";
import { LABELS } from "@/lib/labels";
import { RISK_SIGNALS } from "@/lib/types";

type Condition = { signal?: string; from?: string; to?: string; threshold?: number; windowSeconds?: number; allowedCountries?: string[] };

const HINTS: Record<string, string> = {
  NEW_DEVICE: "이 사람이 전에 로그인한 적 없는 브라우저면 잡힙니다",
  UNUSUAL_TIME: "시작~끝 밖의 시각이면 잡힙니다 (한국 시각)",
  FAILED_LOGIN_BURST: "로그인 직전에 비밀번호를 연속으로 틀린 횟수",
  MASS_ACCESS: "정한 시간 안에 권한 판정을 요청한 횟수",
  FOREIGN_IP: "IAM 서버에 GeoIP 국가 DB나 IP 대역별 국가를 설정했을 때만 잡힙니다. 국가를 모르는 IP(사내망 등)는 잡히지 않습니다",
};

/** 신호를 고르면 그 신호에 필요한 값만 보여준다. 비운 칸은 엔진 기본값 */
export function ConditionFields({ initial }: { initial?: Condition }) {
  const [signal, setSignal] = useState(initial?.signal ?? "NEW_DEVICE");
  return (
    <>
      <Field label="신호" hint={HINTS[signal]}>
        <Select name="signal" value={signal} onChange={(e) => setSignal(e.target.value)}>
          <Options values={RISK_SIGNALS} labels={LABELS.riskSignal} />
        </Select>
      </Field>
      {signal === "UNUSUAL_TIME" && (
        <>
          <Field label="업무 시작" hint="기본 07:00">
            <Input name="from" type="time" defaultValue={initial?.from} />
          </Field>
          <Field label="업무 끝" hint="기본 22:00">
            <Input name="to" type="time" defaultValue={initial?.to} />
          </Field>
        </>
      )}
      {(signal === "FAILED_LOGIN_BURST" || signal === "MASS_ACCESS") && (
        <Field label="기준 횟수" hint={signal === "MASS_ACCESS" ? "기본 100회 이상" : "기본 3회 이상"}>
          <Input name="threshold" type="number" min={1} defaultValue={initial?.threshold} />
        </Field>
      )}
      {signal === "MASS_ACCESS" && (
        <Field label="시간 범위 (초)" hint="기본 60초">
          <Input name="windowSeconds" type="number" min={1} defaultValue={initial?.windowSeconds} />
        </Field>
      )}
      {signal === "FOREIGN_IP" && (
        <Field label="허용 국가" hint="쉼표로 구분. 기본 KR">
          <Input name="allowedCountries" placeholder="KR, JP" defaultValue={initial?.allowedCountries?.join(", ")} />
        </Field>
      )}
    </>
  );
}
