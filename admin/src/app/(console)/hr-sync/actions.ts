"use server";

import { refresh } from "next/cache";
import { callIam } from "@/lib/iam-api";
import type { HrSyncResult } from "@/lib/types";

/** 실행 결과. 성공하면 레코드별 결과를 함께 돌려준다 */
export type HrSyncState = { ok: boolean; message: string; result?: HrSyncResult } | null;

/** 붙여 넣은 JSON(직원 배열, 또는 employees 를 가진 객체)을 미리보기나 반영으로 보낸다 */
export async function runHrSync(_: HrSyncState, form: FormData): Promise<HrSyncState> {
  const dryRun = form.get("mode") !== "apply";
  let employees: unknown;
  try {
    const parsed: unknown = JSON.parse(String(form.get("employees") ?? ""));
    employees = Array.isArray(parsed) ? parsed : (parsed as { employees?: unknown } | null)?.employees;
  } catch {
    return { ok: false, message: "JSON 형식이 올바르지 않습니다. 직원 배열([...])을 붙여 넣으세요" };
  }
  if (!Array.isArray(employees) || employees.length === 0) {
    return { ok: false, message: "직원 배열([...])에 한 명 이상 넣으세요" };
  }

  const result = await callIam<HrSyncResult>(
    `/api/v1/hr/sync?dryRun=${dryRun}`,
    { method: "POST", body: JSON.stringify({ employees, reportMissing: form.get("reportMissing") === "on" }) },
    "/hr-sync",
  );
  if (!result.ok) return { ok: false, message: result.message };
  refresh();
  const errors = result.data.counts.ERROR ?? 0;
  const head = dryRun ? "미리보기를 마쳤습니다. 반영하지 않았습니다" : "반영했습니다";
  return { ok: true, message: errors > 0 ? `${head} (오류 ${errors}건)` : head, result: result.data };
}
