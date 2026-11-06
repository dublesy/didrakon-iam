"use client";

import { useState } from "react";
import { Field, Select } from "@/components/ui";

type Option = { id: number; label: string };

const KIND_LABELS = { role: "역할", resource: "리소스", permission: "권한" } as const;
type Kind = keyof typeof KIND_LABELS;

/** 정책 대상: 종류를 고르면 해당 목록이 나온다 */
export function TargetFields({ options }: { options: Record<Kind, Option[]> }) {
  const [kind, setKind] = useState<Kind>("role");
  return (
    <>
      <Field label="대상 종류">
        <Select name="targetKind" value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
          {(Object.keys(KIND_LABELS) as Kind[]).map((k) => (
            <option key={k} value={k}>
              {KIND_LABELS[k]}
            </option>
          ))}
        </Select>
      </Field>
      <Field label="대상">
        <Select key={kind} name="targetId" required>
          {options[kind].map((o) => (
            <option key={o.id} value={o.id}>
              {o.label}
            </option>
          ))}
        </Select>
      </Field>
    </>
  );
}
