"use client";

import { useState } from "react";
import { ActionForm } from "@/components/action-form";
import { Field, Input, Options, Select } from "@/components/ui";
import { LABELS } from "@/lib/labels";
import { ATTRIBUTE_SOURCES, OPERATORS } from "@/lib/types";
import { createVersion } from "./actions";

type Row = { key: number; ruleGroup: number; attributeSource: string; attributeName: string; operator: string; attributeValue: string };

const emptyRow = (key: number, ruleGroup = 0): Row => ({ key, ruleGroup, attributeSource: "SUBJECT", attributeName: "", operator: "EQ", attributeValue: "" });

/** 새 규칙 버전 편집기. 행을 JSON 으로 묶어 hidden 입력 rules 로 보낸다 */
export function RuleEditor({ policyId }: { policyId: number }) {
  const [rows, setRows] = useState<Row[]>([emptyRow(0)]);
  const [nextKey, setNextKey] = useState(1);

  const update = (key: number, patch: Partial<Row>) => setRows(rows.map((r) => (r.key === key ? { ...r, ...patch } : r)));
  const add = () => {
    setRows([...rows, emptyRow(nextKey, rows.at(-1)?.ruleGroup ?? 0)]);
    setNextKey(nextKey + 1);
  };
  const remove = (key: number) => setRows(rows.filter((r) => r.key !== key));
  const serialized = JSON.stringify(rows.map((r) => ({ ruleGroup: r.ruleGroup, attributeSource: r.attributeSource, attributeName: r.attributeName, operator: r.operator, attributeValue: r.attributeValue })));

  return (
    <ActionForm action={createVersion} submitLabel="새 버전 만들기">
      <input type="hidden" name="policyId" value={policyId} />
      <input type="hidden" name="rules" value={serialized} />
      <div className="space-y-2">
        {rows.map((r, i) => (
          <div key={r.key} className="grid grid-cols-2 items-end gap-2 md:grid-cols-[6rem_8rem_1fr_7rem_1fr_auto]">
            <Field label={`${i + 1}. 그룹`}>
              <Input type="number" min={0} value={r.ruleGroup} onChange={(e) => update(r.key, { ruleGroup: Number(e.target.value) || 0 })} />
            </Field>
            <Field label="속성 출처">
              <Select value={r.attributeSource} onChange={(e) => update(r.key, { attributeSource: e.target.value })}>
                <Options values={ATTRIBUTE_SOURCES} labels={LABELS.attributeSource} />
              </Select>
            </Field>
            <Field label="속성 이름">
              <Input value={r.attributeName} required onChange={(e) => update(r.key, { attributeName: e.target.value })} />
            </Field>
            <Field label="연산자">
              <Select value={r.operator} onChange={(e) => update(r.key, { operator: e.target.value })}>
                <Options values={OPERATORS} />
              </Select>
            </Field>
            <Field label="값 (JSON)">
              <Input
                value={r.attributeValue}
                placeholder={r.operator === "EXISTS" ? "비워 둠" : '"KR" · ["KR","JP"] · 10'}
                onChange={(e) => update(r.key, { attributeValue: e.target.value })}
                className="font-mono text-[13px]"
              />
            </Field>
            <button type="button" onClick={() => remove(r.key)} disabled={rows.length === 1} className="h-9 rounded-lg px-2 text-xs font-medium text-danger transition-colors hover:bg-danger-soft disabled:opacity-40 disabled:hover:bg-transparent">
              삭제
            </button>
          </div>
        ))}
        <button type="button" onClick={add} className="h-9 rounded-lg border border-line-strong bg-surface px-3 font-medium text-ink transition-colors hover:bg-panel">
          규칙 추가
        </button>
      </div>
      <div className="mt-3 max-w-xl">
        <Field label="변경 사유 (선택)">
          <Input name="changeReason" maxLength={1000} />
        </Field>
      </div>
    </ActionForm>
  );
}
