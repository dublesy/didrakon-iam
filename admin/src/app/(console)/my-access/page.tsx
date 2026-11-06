import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, PageHeader, Select, Table } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query } from "@/lib/queries";
import type { AccessOptions, AccessRequestView, BreakGlassPolicy, BreakGlassSession, Delegation, MyDelegations } from "@/lib/types";
import { activateBreakGlass, cancelRequest, delegateRole, endMyBreakGlass, endMyDelegation, requestAccess } from "./actions";

const here = "/my-access";

const REQUEST_TONES: Record<string, "zinc" | "green" | "red" | "amber"> = { PENDING: "amber", APPROVED: "green", REJECTED: "red", CANCELLED: "zinc", EXPIRED: "zinc" };
const DELEGATION_TONES: Record<string, "zinc" | "green" | "amber"> = { PENDING: "amber", ACTIVE: "green", EXPIRED: "zinc", REVOKED: "zinc" };

export default function MyAccessPage() {
  return (
    <>
      <PageHeader
        title="내 권한 요청"
        description="필요한 역할을 기간을 정해 요청하고, 내 역할을 다른 사람에게 맡기고, 급한 상황에 비상 접근을 시작합니다. 모든 요청·위임·비상 접근은 감사 기록에 남습니다."
      />
      <Suspense fallback={<Loading />}>
        <MyAccess />
      </Suspense>
    </>
  );
}

async function MyAccess() {
  const [me, options, requests, delegations, policies, sessions] = await Promise.all([
    query<{ authenticationMethods: string[] }>("/api/v1/me", here),
    query<AccessOptions>("/api/v1/me/access-options", here),
    query<AccessRequestView[]>("/api/v1/me/access-requests", here),
    query<MyDelegations>("/api/v1/me/delegations", here),
    query<BreakGlassPolicy[]>("/api/v1/me/break-glass-policies", here),
    query<BreakGlassSession[]>("/api/v1/me/break-glass-sessions", here),
  ]);
  const mfaDone = me.authenticationMethods.some((m) => m === "otp" || m === "hwk");

  return (
    <div className="space-y-6">
      <AccessRequests options={options} requests={requests} />
      <Delegations options={options} delegations={delegations} />
      <BreakGlass policies={policies} sessions={sessions} mfaDone={mfaDone} />
    </div>
  );
}

// ---------- 임시 권한 요청 ----------

function AccessRequests({ options, requests }: { options: AccessOptions; requests: AccessRequestView[] }) {
  const globalScope = options.scopes.find((s) => s.scopeCode === "GLOBAL")?.scopeId;
  return (
    <section className="space-y-4">
      <AddPanel label="권한 요청">
        <ActionForm action={requestAccess} submitLabel="요청" resetOnSuccess>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <Field label="역할">
              <Select name="roleId" required>
                {options.roles.map((r) => (
                  <option key={r.roleId} value={r.roleId}>
                    {r.roleName}
                    {r.isPrivileged ? " (특권)" : ""}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="범위">
              <Select name="scopeId" defaultValue={globalScope}>
                {options.scopes.map((s) => (
                  <option key={s.scopeId} value={s.scopeId}>
                    {s.scopeName} ({s.scopeCode})
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="시작 (선택)" hint="비우면 지금부터. 역할은 승인된 뒤에 생깁니다">
              <Input name="start" type="datetime-local" />
            </Field>
            <Field label="사용 시간 (시간)" hint="최대 720시간 (30일)">
              <Input name="hours" type="number" required min={1} max={720} defaultValue={8} />
            </Field>
          </div>
          <div className="mt-3">
            <Field label="사유">
              <Input name="reason" required maxLength={1000} placeholder="어떤 일에 왜 필요한지" />
            </Field>
          </div>
        </ActionForm>
      </AddPanel>

      <Card title="내 요청">
        <Table headers={["역할", "범위", "유형", "기간", "사유", "상태", "결정", ""]} empty={requests.length === 0} emptyText="요청한 적이 없습니다">
          {requests.map((r) => (
            <tr key={r.requestId} className="[&>td]:py-2.5 [&>td]:align-top">
              <td>{r.roleName ?? r.roleId}</td>
              <td>
                <Mono>{r.scopeCode ?? r.scopeId}</Mono>
              </td>
              <td className="whitespace-nowrap">{label("requestType", r.requestType)}</td>
              <td className="font-mono text-xs whitespace-nowrap text-ink-2 tabular-nums">
                {formatTime(r.requestedStart)} ~ {formatTime(r.requestedEnd)}
              </td>
              <td className="max-w-[28ch]">{r.reason}</td>
              <td>
                <Badge tone={REQUEST_TONES[r.status] ?? "zinc"}>{label("requestStatus", r.status)}</Badge>
                {r.closedAt && <div className="mt-1 text-xs whitespace-nowrap text-ink-3 tabular-nums">{formatTime(r.closedAt)}</div>}
              </td>
              <td>
                {r.decisions.length === 0 ? (
                  <span className="text-ink-3">—</span>
                ) : (
                  <ul className="space-y-1">
                    {r.decisions.map((d) => (
                      <li key={`${d.approverId}-${d.decidedAt}`}>
                        {d.approverName ?? d.approverId} {label("approvalStatus", d.status)}
                        {d.comment && <div className="text-xs text-ink-2">{d.comment}</div>}
                      </li>
                    ))}
                  </ul>
                )}
              </td>
              <td>
                {r.status === "PENDING" && (
                  <span className="flex justify-end">
                    <RowAction action={cancelRequest} label="취소" hidden={{ requestId: r.requestId }} confirmMessage="이 요청을 취소할까요?" />
                  </span>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </section>
  );
}

// ---------- 위임 ----------

function Delegations({ options, delegations }: { options: AccessOptions; delegations: MyDelegations }) {
  return (
    <section className="space-y-4">
      {options.delegatable.length === 0 ? (
        <p className="text-ink-3">직접 가진 역할이 없어 위임할 수 없습니다. 위임받은 역할은 다시 위임할 수 없습니다.</p>
      ) : (
        <AddPanel label="역할 위임">
          <ActionForm action={delegateRole} submitLabel="위임" resetOnSuccess>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <Field label="위임할 역할" hint="직접 가진 역할만 고를 수 있습니다">
                <Select name="roleScope" required>
                  {options.delegatable.map((d) => (
                    <option key={`${d.roleId}:${d.scopeId}`} value={`${d.roleId}:${d.scopeId}`}>
                      {d.roleName} ({d.scopeCode})
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="대리인 사번">
                <Input name="empNo" required maxLength={50} autoComplete="off" />
              </Field>
              <Field label="시작 (선택)" hint="비우면 지금부터">
                <Input name="start" type="datetime-local" />
              </Field>
              <Field label="끝">
                <Input name="end" type="datetime-local" required />
              </Field>
            </div>
            <div className="mt-3">
              <Field label="사유">
                <Input name="reason" required maxLength={1000} placeholder="휴가·출장 등" />
              </Field>
            </div>
          </ActionForm>
        </AddPanel>
      )}

      <Card title="내가 한 위임">
        <DelegationTable rows={delegations.given} who="delegate" />
      </Card>
      <Card title="내가 받은 위임">
        <DelegationTable rows={delegations.received} who="delegator" />
      </Card>
    </section>
  );
}

function DelegationTable({ rows, who }: { rows: Delegation[]; who: "delegate" | "delegator" }) {
  const canEnd = who === "delegate";
  return (
    <Table headers={[canEnd ? "대리인" : "위임자", "역할", "범위", "기간", "사유", "상태", ""]} empty={rows.length === 0} emptyText="위임이 없습니다">
      {rows.map((d) => {
        const open = d.status === "PENDING" || d.status === "ACTIVE";
        return (
          <tr key={d.delegationId} className={`[&>td]:py-2.5 [&>td]:align-top ${open ? "" : "text-ink-3"}`}>
            <td>{canEnd ? (d.delegateName ?? d.delegateId) : (d.delegatorName ?? d.delegatorId)}</td>
            <td>{d.roleName ?? d.roleId}</td>
            <td>
              <Mono>{d.scopeCode ?? d.scopeId}</Mono>
            </td>
            <td className="font-mono text-xs whitespace-nowrap tabular-nums">
              {formatTime(d.startTime)} ~ {formatTime(d.endTime)}
            </td>
            <td className="max-w-[28ch]">{d.reason}</td>
            <td>
              <Badge tone={DELEGATION_TONES[d.status] ?? "zinc"}>{label("delegationStatus", d.status)}</Badge>
            </td>
            <td>
              {canEnd && open && (
                <span className="flex justify-end">
                  <RowAction
                    action={endMyDelegation}
                    label="거두기"
                    hidden={{ delegationId: d.delegationId }}
                    confirmMessage={`${d.delegateName ?? d.delegateId} 님에게 한 '${d.roleName ?? d.roleId}' 위임을 지금 거둘까요?`}
                  />
                </span>
              )}
            </td>
          </tr>
        );
      })}
    </Table>
  );
}

// ---------- 비상 접근 ----------

function BreakGlass({ policies, sessions, mfaDone }: { policies: BreakGlassPolicy[]; sessions: BreakGlassSession[]; mfaDone: boolean }) {
  const needsMfa = !mfaDone && policies.some((p) => p.requireMfa);
  return (
    <section className="space-y-4">
      <Card title="비상 접근">
        <p className="mb-4 text-ink-2">장애처럼 급한 상황에만 씁니다. 시작하면 정책의 최대 시간 동안 역할이 생기고, 일이 끝나면 직접 끝내세요.</p>
        {needsMfa && (
          <div role="status" className="mb-4 rounded-lg bg-warning-soft p-4 text-warning">
            2단계 인증이 필요한 정책은 인증 앱이나 패스키로 로그인해야 시작할 수 있습니다. 지금은 비밀번호로만 로그인했습니다.{" "}
            <Link href="/mfa" className="font-medium underline underline-offset-2">
              2단계 인증 설정
            </Link>
          </div>
        )}
        <Table headers={["정책", "역할", "범위", "최대 시간", "조건", "시작"]} empty={policies.length === 0} emptyText="쓸 수 있는 비상 접근 정책이 없습니다">
          {policies.map((p) => (
            <tr key={p.policyId} className="[&>td]:py-3 [&>td]:align-top">
              <td className="font-medium">{p.policyName}</td>
              <td>{p.roleName ?? p.roleId}</td>
              <td>
                <Mono>{p.scopeCode ?? p.scopeId}</Mono>
              </td>
              <td className="tabular-nums">{p.maxDurationMinutes}분</td>
              <td>
                <span className="flex flex-wrap gap-1">
                  {p.requireMfa && <Badge tone={mfaDone ? "zinc" : "amber"}>2단계 인증</Badge>}
                  {p.requireApproval && <Badge>승인 후 시작</Badge>}
                  {p.requireReason && <Badge>사유</Badge>}
                </span>
              </td>
              <td>
                <ActionForm
                  action={activateBreakGlass}
                  submitLabel={p.requireApproval ? "승인 요청" : "시작"}
                  variant="danger"
                  confirmMessage={`'${p.policyName}' 비상 접근을 ${p.requireApproval ? "요청" : "시작"}할까요? 감사 기록에 남습니다`}
                >
                  <input type="hidden" name="policyId" value={p.policyId} />
                  <Field label={p.requireReason ? "사유" : "사유 (선택)"}>
                    <Input name="reason" required={p.requireReason} maxLength={1000} />
                  </Field>
                </ActionForm>
              </td>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title="내 비상 접근 기록">
        <Table headers={["정책", "역할", "사유", "시작", "끝", "상태", ""]} empty={sessions.length === 0} emptyText="비상 접근을 쓴 적이 없습니다">
          {sessions.map((s) => (
            <tr key={s.sessionId}>
              <td>{s.policyName ?? s.policyId}</td>
              <td>{s.roleName ?? "—"}</td>
              <td className="max-w-[28ch]">{s.reason ?? "—"}</td>
              <td className="tabular-nums whitespace-nowrap">{formatTime(s.startTime)}</td>
              <td className="tabular-nums whitespace-nowrap">{formatTime(s.endTime)}</td>
              <td>
                <Badge tone={s.status === "ACTIVE" ? "amber" : "zinc"}>{label("breakGlassStatus", s.status)}</Badge>
              </td>
              <td>
                {s.status === "ACTIVE" && (
                  <span className="flex justify-end">
                    <RowAction action={endMyBreakGlass} label="끝내기" hidden={{ sessionId: s.sessionId }} confirmMessage="비상 접근을 지금 끝낼까요? 받은 역할이 바로 회수됩니다" />
                  </span>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </section>
  );
}
