import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { Badge, Card, Field, Input, Loading, Mono, PageHeader, Table } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import type { AccessRequest, AccessRequestView, Role, Scope } from "@/lib/types";
import { approveRequest, rejectRequest } from "./actions";

const RISK_TONES: Record<string, "zinc" | "amber" | "red"> = { LOW: "zinc", MEDIUM: "amber", HIGH: "red", CRITICAL: "red" };

export default function ApprovalsPage() {
  return (
    <>
      <PageHeader
        title="승인 대기"
        description="권한 요청을 승인하거나 반려합니다. 승인 정책에 따라 여러 명의 승인이 필요할 수 있고, 본인 요청은 승인할 수 없습니다"
      />
      <div className="space-y-6">
        <Suspense fallback={<Loading />}>
          <PendingList />
        </Suspense>
        <Suspense fallback={<Loading />}>
          <History />
        </Suspense>
      </div>
    </>
  );
}

async function PendingList() {
  const here = "/approvals";
  const [requests, roles, scopes, me] = await Promise.all([
    query<AccessRequest[]>("/api/v1/access-requests/pending", here),
    query<Role[]>("/api/v1/roles", here),
    query<Scope[]>("/api/v1/scopes", here),
    query<{ subjectId: number }>("/api/v1/me", here),
  ]);
  const names = await subjectNames(requests.map((r) => r.subjectId), here);
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  const scopeCode = new Map(scopes.map((s) => [s.scopeId, s.scopeCode]));

  return (
    <Card>
      <Table headers={["요청자", "역할", "범위", "유형", "위험도", "사유", "요청 기간", "처리"]} empty={requests.length === 0} emptyText="승인을 기다리는 요청이 없습니다">
        {requests.map((r) => (
          <tr key={r.requestId} className="[&>td]:py-3 [&>td]:align-top">
            <td>{names.get(r.subjectId) ?? r.subjectId}</td>
            <td>{roleName.get(r.roleId) ?? r.roleId}</td>
            <td>
              <Mono>{scopeCode.get(r.scopeId) ?? r.scopeId}</Mono>
            </td>
            <td className="whitespace-nowrap">{label("requestType", r.requestType)}</td>
            <td>
              <Badge tone={RISK_TONES[r.riskLevel] ?? "zinc"}>{label("risk", r.riskLevel)}</Badge>
            </td>
            <td>{r.reason}</td>
            <td className="font-mono text-xs whitespace-nowrap text-ink-2 tabular-nums">
              {formatTime(r.requestedStart)} ~ {formatTime(r.requestedEnd)}
            </td>
            <td>
              {r.subjectId === me.subjectId ? (
                // 본인 요청은 본인이 승인·반려할 수 없다 (서버도 거부한다)
                <span className="text-ink-3">본인 요청이라 다른 승인자가 처리합니다</span>
              ) : (
                <div className="flex flex-col gap-3">
                  <ActionForm action={approveRequest} submitLabel="승인">
                    <input type="hidden" name="requestId" value={r.requestId} />
                    <Field label="승인 의견 (선택)">
                      <Input name="comment" maxLength={1000} />
                    </Field>
                  </ActionForm>
                  <ActionForm action={rejectRequest} submitLabel="반려" variant="danger" confirmMessage="이 요청을 반려할까요?">
                    <input type="hidden" name="requestId" value={r.requestId} />
                    <Field label="반려 의견 (선택)">
                      <Input name="comment" maxLength={1000} />
                    </Field>
                  </ActionForm>
                </div>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

const STATUS_TONES: Record<string, "zinc" | "green" | "red"> = { APPROVED: "green", REJECTED: "red", CANCELLED: "zinc", EXPIRED: "zinc" };

/** 처리가 끝난 요청. 취소·만료는 승인자 결정이 없다 (취소는 요청자, 만료는 기간 종료로 끝난다) */
async function History() {
  const history = await query<AccessRequestView[]>("/api/v1/access-requests/history", "/approvals");

  return (
    <Card title="처리 기록">
      <p className="mb-4 text-ink-2">승인·반려·취소·만료된 요청 최근 200건입니다.</p>
      <Table headers={["요청자", "역할", "범위", "유형", "사유", "요청 기간", "결과", "결정"]} empty={history.length === 0} emptyText="처리된 요청이 없습니다">
        {history.map((r) => (
          <tr key={r.requestId} className="[&>td]:py-2.5 [&>td]:align-top">
            <td>
              <div>{r.subjectName ?? r.subjectId}</div>
              <div className="text-xs text-ink-3 tabular-nums">요청 {formatTime(r.createdAt)}</div>
            </td>
            <td>{r.roleName ?? r.roleId}</td>
            <td>
              <Mono>{r.scopeCode ?? r.scopeId}</Mono>
            </td>
            <td className="whitespace-nowrap">{label("requestType", r.requestType)}</td>
            <td className="max-w-[28ch]">{r.reason}</td>
            <td className="font-mono text-xs whitespace-nowrap text-ink-2 tabular-nums">
              {formatTime(r.requestedStart)} ~ {formatTime(r.requestedEnd)}
            </td>
            <td>
              <Badge tone={STATUS_TONES[r.status] ?? "zinc"}>{label("requestStatus", r.status)}</Badge>
              {r.closedAt && <div className="mt-1 text-xs whitespace-nowrap text-ink-3 tabular-nums">{formatTime(r.closedAt)}</div>}
            </td>
            <td>
              <Decisions request={r} />
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function Decisions({ request }: { request: AccessRequestView }) {
  if (request.decisions.length === 0) {
    return <span className="text-ink-3">{request.status === "CANCELLED" ? "요청자 취소" : request.status === "EXPIRED" ? "기간 종료" : "—"}</span>;
  }
  return (
    <ul className="space-y-1">
      {request.decisions.map((d) => (
        <li key={`${d.approverId}-${d.decidedAt}`}>
          <span className="font-medium">{d.approverName ?? d.approverId}</span> {label("approvalStatus", d.status)}
          <span className="ml-1 text-xs text-ink-3 tabular-nums">{formatTime(d.decidedAt)}</span>
          {d.comment && <div className="text-xs text-ink-2">{d.comment}</div>}
        </li>
      ))}
    </ul>
  );
}
