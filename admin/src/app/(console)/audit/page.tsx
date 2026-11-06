import { connection } from "next/server";
import { Suspense } from "react";
import { Card, Checkbox, Field, Input, Loading, Mono, PageHeader, Table } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import { AUDIT_EVENT_TYPES, type AuditEvent } from "@/lib/types";

type SearchParams = PageProps<"/audit">["searchParams"];

const KST_OFFSET_MS = 9 * 60 * 60 * 1000;

/** ISO 시각 → datetime-local 값 (한국 시각) */
const toLocalInput = (time: number) => new Date(time + KST_OFFSET_MS).toISOString().slice(0, 16);

/** datetime-local 값 (한국 시각) → ISO 시각. 형식이 틀리면 undefined */
function toIso(value: string): string | undefined {
  const date = new Date(`${value}:00+09:00`);
  return Number.isNaN(date.getTime()) ? undefined : date.toISOString();
}

/** 기본 기간: 최근 24시간 */
function lastDay() {
  const now = Date.now();
  return { from: toLocalInput(now - 24 * 60 * 60 * 1000), to: toLocalInput(now) };
}

const one = (v: string | string[] | undefined) => (typeof v === "string" ? v : undefined);

export default function AuditPage({ searchParams }: PageProps<"/audit">) {
  return (
    <>
      <PageHeader title="감사 기록" description="로그인, 권한·정책 변경 등 감사 이벤트를 기간으로 찾습니다. 시각은 한국 시각입니다" />
      <Suspense fallback={<Loading />}>
        <AuditSearch searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function AuditSearch({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  // 기본 기간은 현재 시각 기준이라 사전 렌더링이 아니라 요청 시점에 계산한다
  await connection();
  const defaults = lastDay();
  const from = one(params.from) ?? defaults.from;
  const to = one(params.to) ?? defaults.to;
  const subjectId = one(params.subjectId)?.trim() ?? "";
  const limit = Math.min(1000, Math.max(1, Number(one(params.limit) ?? 100) || 100));
  const rawTypes = params.types === undefined ? [] : [params.types].flat();
  const types = AUDIT_EVENT_TYPES.filter((t) => rawTypes.includes(t));

  const fromIso = toIso(from);
  const toIsoValue = toIso(to);

  return (
    <div className="space-y-6">
      <Card>
        <form className="space-y-4" role="search">
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Field label="시작 (한국 시각)">
              <Input name="from" type="datetime-local" defaultValue={from} required />
            </Field>
            <Field label="끝 (한국 시각)">
              <Input name="to" type="datetime-local" defaultValue={to} required />
            </Field>
            <Field label="대상 subject ID (선택)">
              <Input name="subjectId" type="number" min={1} defaultValue={subjectId} />
            </Field>
            <Field label="최대 건수">
              <Input name="limit" type="number" min={1} max={1000} defaultValue={limit} />
            </Field>
          </div>
          <fieldset>
            <legend className="mb-1 text-[13px] font-medium text-ink-2">이벤트 유형 (비우면 전체)</legend>
            <div className="flex flex-wrap gap-x-4">
              {AUDIT_EVENT_TYPES.map((t) => (
                <Checkbox key={t} name="types" value={t} label={LABELS.auditType[t]} defaultChecked={types.includes(t)} />
              ))}
            </div>
          </fieldset>
          <button type="submit" className="h-9 rounded-lg bg-accent px-3.5 font-medium text-white transition-colors hover:bg-accent-hover">
            검색
          </button>
        </form>
      </Card>
      {fromIso && toIsoValue ? (
        <Suspense fallback={<Loading />}>
          <AuditResults from={fromIso} to={toIsoValue} subjectId={subjectId} types={types} limit={limit} />
        </Suspense>
      ) : (
        <p role="alert" className="rounded-xl bg-danger-soft p-5 text-danger">
          기간 형식이 올바르지 않습니다. 시작과 끝을 다시 고르세요
        </p>
      )}
    </div>
  );
}

async function AuditResults({ from, to, subjectId, types, limit }: { from: string; to: string; subjectId: string; types: string[]; limit: number }) {
  const qs = new URLSearchParams({ from, to, limit: String(limit) });
  if (subjectId) qs.set("subjectId", subjectId);
  types.forEach((t) => qs.append("types", t));
  const events = await query<AuditEvent[]>(`/api/v1/audit/events?${qs}`, "/audit");
  const names = await subjectNames(
    events.flatMap((e) => [e.actorSubjectId, e.targetSubjectId]).filter((id): id is number => id !== null),
    "/audit",
  );
  const name = (id: number | null) => (id === null ? "—" : (names.get(id) ?? id));

  return (
    <Card title={`결과 ${events.length}건`}>
      <Table headers={["시각", "유형", "동작", "처리자", "대상", "리소스", "사유", "추적 ID", "IP"]} empty={events.length === 0} emptyText="이 조건에 맞는 기록이 없습니다">
        {events.map((e) => (
          <tr key={e.eventId} className="[&>td]:py-2 [&>td]:align-top">
            <td className="font-mono text-xs whitespace-nowrap text-ink-2 tabular-nums">{formatTime(e.createdAt)}</td>
            <td className="whitespace-nowrap">{label("auditType", e.eventType)}</td>
            <td className="whitespace-nowrap">{label("auditAction", e.action)}</td>
            <td>{name(e.actorSubjectId)}</td>
            <td>{name(e.targetSubjectId)}</td>
            <td>
              {e.resourceType ? label("resourceType", e.resourceType) : "—"}
              {e.resourceId && (
                <>
                  {" "}
                  <Mono>{e.resourceId}</Mono>
                </>
              )}
              {(e.beforeValue || e.afterValue) && (
                <details className="mt-1">
                  <summary className="cursor-pointer text-xs text-ink-3 hover:text-accent">변경 내용</summary>
                  {e.beforeValue && <JsonBlock caption="변경 전" value={e.beforeValue} />}
                  {e.afterValue && <JsonBlock caption="변경 후" value={e.afterValue} />}
                </details>
              )}
            </td>
            <td>{e.reason ?? "—"}</td>
            <td>{e.traceId ? <Mono>{e.traceId}</Mono> : "—"}</td>
            <td>{e.ipAddress ? <Mono>{e.ipAddress}</Mono> : "—"}</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function JsonBlock({ caption, value }: { caption: string; value: string }) {
  return (
    <div className="mt-1">
      <span className="text-xs text-ink-3">{caption}</span>
      <pre className="max-w-md overflow-x-auto rounded-lg bg-panel p-2 font-mono text-xs text-ink-2">{pretty(value)}</pre>
    </div>
  );
}

/** JSON 이면 들여쓰기해서 보여준다 */
function pretty(value: string): string {
  try {
    return JSON.stringify(JSON.parse(value), null, 2);
  } catch {
    return value;
  }
}
