"use client";

import { useActionState, useState } from "react";
import { Badge, Checkbox, Field, Table, Textarea, buttonClass } from "@/components/ui";
import { label } from "@/lib/labels";
import { HR_SYNC_ACTIONS } from "@/lib/types";
import { runHrSync } from "./actions";

/** 결과 표에 보여줄 최대 행 수. 변경 없는 레코드는 빼고 센다 */
const MAX_ROWS = 200;

const EXAMPLE = `[
  { "empNo": "E1001", "name": "홍길동", "email": "hong@example.com", "orgCode": "DEV-TEAM",
    "jobTitle": "팀장", "isManager": true, "employmentStatus": "EMPLOYED" }
]`;

/** 붙여 넣은 직원 목록을 미리보기 또는 반영한다. 반영은 확인을 받는다 */
export function HrSyncForm() {
  const [state, action, pending] = useActionState(runHrSync, null);
  // 폼 액션이 끝나면 React 가 입력을 비우므로, 다시 고쳐 보낼 수 있게 값을 직접 가진다
  const [employees, setEmployees] = useState("");
  const result = state?.result;
  const changed = result?.records.filter((r) => !(r.actions.length === 1 && r.actions[0] === "UNCHANGED")) ?? [];

  return (
    <div className="space-y-5">
      <form
        action={action}
        onSubmit={(e) => {
          const submitter = (e.nativeEvent as SubmitEvent).submitter as HTMLButtonElement | null;
          if (submitter?.value === "apply" && !window.confirm("붙여 넣은 내용을 실제로 반영할까요? 생성·이동·휴직·퇴사가 바로 처리되고, 퇴사는 되돌릴 수 없습니다")) {
            e.preventDefault();
          }
        }}
      >
        <Field label="직원 목록 (JSON 배열)" hint="API 요청의 employees 와 같은 형식입니다. 먼저 미리보기로 결과를 확인하세요">
          <Textarea
            name="employees"
            rows={8}
            required
            placeholder={EXAMPLE}
            value={employees}
            onChange={(e) => setEmployees(e.target.value)}
          />
        </Field>
        <Checkbox name="reportMissing" label="목록에 없는 사용 중 사용자도 알려주기 (퇴사 처리는 하지 않음)" />
        <div className="mt-2 flex flex-wrap items-center gap-3">
          <button type="submit" name="mode" value="preview" disabled={pending} className={buttonClass.primary}>
            {pending ? "처리 중" : "미리보기"}
          </button>
          <button type="submit" name="mode" value="apply" disabled={pending} className={buttonClass.secondary}>
            반영
          </button>
          {state && (
            <p role={state.ok ? "status" : "alert"} className={state.ok ? "text-success" : "text-danger"}>
              {state.message}
            </p>
          )}
        </div>
      </form>

      {result && (
        <div className="space-y-4 border-t border-line pt-4">
          <div className="flex flex-wrap items-center gap-2">
            <Badge tone={result.dryRun ? "zinc" : "blue"}>{result.dryRun ? "미리보기" : "반영"}</Badge>
            {HR_SYNC_ACTIONS.filter((a) => result.counts[a]).map((a) => (
              <Badge key={a} tone={a === "ERROR" ? "red" : "zinc"}>
                {label("hrAction", a)} <span className="ml-1 tabular-nums">{result.counts[a]}</span>
              </Badge>
            ))}
          </div>
          <Table headers={["사번", "결과", "내용"]} empty={changed.length === 0} emptyText="바뀌는 레코드가 없습니다">
            {changed.slice(0, MAX_ROWS).map((r, i) => (
              <tr key={`${r.empNo}-${i}`}>
                <td className="font-mono text-[12px]">{r.empNo ?? "—"}</td>
                <td>
                  <span className="flex flex-wrap gap-1">
                    {r.actions.map((a) => (
                      <Badge key={a} tone={a === "ERROR" ? "red" : "zinc"}>
                        {label("hrAction", a)}
                      </Badge>
                    ))}
                  </span>
                </td>
                <td className={r.actions.includes("ERROR") ? "text-danger" : "text-ink-2"}>{r.message ?? ""}</td>
              </tr>
            ))}
          </Table>
          {changed.length > MAX_ROWS && <p className="text-ink-3">앞 {MAX_ROWS}건만 보여줍니다 (전체 {changed.length}건)</p>}
          {result.missing && (
            <div>
              <h3 className="mb-2 font-medium text-ink">목록에 없는 사용 중 사용자 {result.missing.length}명</h3>
              {result.missing.length === 0 ? (
                <p className="text-ink-3">없습니다</p>
              ) : (
                <p className="text-ink-2">
                  {result.missing.map((m) => `${m.name}(${m.empNo})`).join(", ")}
                </p>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
