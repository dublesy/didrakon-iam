import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query } from "@/lib/queries";
import type { AccessOptions, BreakGlassPolicy, BreakGlassSession, GroupOption } from "@/lib/types";
import { changeBreakGlassPolicyActive, createBreakGlassPolicy, endBreakGlassSession, updateBreakGlassPolicy } from "./actions";

const SESSION_TONES: Record<string, "zinc" | "amber"> = { ACTIVE: "amber", EXPIRED: "zinc", REVOKED: "zinc" };

export default function BreakGlassPage({ searchParams }: PageProps<"/break-glass">) {
  return (
    <>
      <PageHeader
        title="비상 접근"
        description="장애 같은 급한 상황에 역할을 최대 시간 동안만 쓰게 하는 정책입니다. 사용자는 내 권한 요청 화면에서 시작하고, 직무 분리 검사를 건너뛰는 대신 모든 시작·종료가 감사 기록에 남습니다. 정책은 지우지 않고 끕니다."
      />
      <Suspense fallback={<Loading />}>
        <BreakGlassContent searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function BreakGlassContent({ searchParams }: { searchParams: PageProps<"/break-glass">["searchParams"] }) {
  const here = "/break-glass";
  const params = await searchParams;
  const [policies, sessions, options, groups] = await Promise.all([
    query<BreakGlassPolicy[]>("/api/v1/break-glass-policies", here),
    query<BreakGlassSession[]>("/api/v1/break-glass-sessions", here),
    query<AccessOptions>("/api/v1/me/access-options", here),
    query<GroupOption[]>("/api/v1/break-glass-policies/group-options", here),
  ]);
  const editing = policies.find((p) => String(p.policyId) === params.edit);

  return (
    <div className="space-y-6">
      {editing ? (
        <Card title={`${editing.policyName} 수정`} actions={<Link href={here} className="text-ink-2 hover:text-ink">닫기</Link>}>
          <p className="mb-4 text-ink-2">
            역할 <span className="font-medium text-ink">{editing.roleName ?? editing.roleId}</span> · 범위 <Mono>{editing.scopeCode ?? editing.scopeId}</Mono> 는
            바꿀 수 없습니다. 바꾸려면 새 정책을 만들고 이 정책을 끄세요.
          </p>
          <ActionForm key={editing.policyId} action={updateBreakGlassPolicy} submitLabel="저장">
            <input type="hidden" name="policyId" value={editing.policyId} />
            <PolicyFields policy={editing} groups={groups} />
          </ActionForm>
        </Card>
      ) : (
        <AddPanel label="정책 추가">
          <ActionForm action={createBreakGlassPolicy} submitLabel="만들기" resetOnSuccess>
            <div className="mb-3 grid grid-cols-1 gap-3 md:grid-cols-2">
              <Field label="역할">
                <Select name="roleId" required>
                  {options.roles.map((r) => (
                    <option key={r.roleId} value={r.roleId}>
                      {r.roleName} ({r.roleCode})
                    </option>
                  ))}
                </Select>
              </Field>
              <Field label="범위">
                <Select name="scopeId" required defaultValue={options.scopes.find((s) => s.scopeCode === "GLOBAL")?.scopeId}>
                  {options.scopes.map((s) => (
                    <option key={s.scopeId} value={s.scopeId}>
                      {s.scopeName} ({s.scopeCode})
                    </option>
                  ))}
                </Select>
              </Field>
            </div>
            <PolicyFields groups={groups} />
          </ActionForm>
        </AddPanel>
      )}

      <Card title="정책">
        <Table headers={["이름", "역할", "범위", "쓸 수 있는 사람", "최대 시간", "조건", "상태", ""]} empty={policies.length === 0} emptyText="비상 접근 정책이 없습니다">
          {policies.map((p) => (
            <tr key={p.policyId} className={p.isActive ? undefined : "text-ink-3"}>
              <td className="font-medium">{p.policyName}</td>
              <td>{p.roleName ?? p.roleId}</td>
              <td>
                <Mono>{p.scopeCode ?? p.scopeId}</Mono>
              </td>
              <td>{p.eligibleGroupId ? (p.eligibleGroupName ?? p.eligibleGroupId) + " 구성원" : <span className="text-ink-3">누구나</span>}</td>
              <td className="tabular-nums">{p.maxDurationMinutes}분</td>
              <td>
                <Conditions policy={p} />
              </td>
              <td>{p.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}</td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link href={`${here}?edit=${p.policyId}`} className={buttonClass.row}>
                    수정
                  </Link>
                  <RowAction
                    action={changeBreakGlassPolicyActive}
                    label={p.isActive ? "끄기" : "켜기"}
                    tone={p.isActive ? "danger" : "neutral"}
                    hidden={{ policyId: p.policyId, active: String(!p.isActive) }}
                    confirmMessage={
                      p.isActive ? `'${p.policyName}' 정책을 끌까요? 새로 시작할 수 없게 되고 승인 대기 중인 요청도 승인할 수 없습니다. 진행 중인 세션은 아래에서 따로 끝내세요` : undefined
                    }
                  />
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>

      <Card title="세션">
        <p className="mb-4 text-ink-2">진행 중인 세션 전부와 최근 100건입니다. 끝내면 그 세션으로 받은 역할이 바로 회수됩니다.</p>
        <Table headers={["사용자", "정책", "역할", "사유", "시작", "끝", "상태", ""]} empty={sessions.length === 0} emptyText="비상 접근 기록이 없습니다">
          {sessions.map((s) => (
            <tr key={s.sessionId} className="[&>td]:py-2.5 [&>td]:align-top">
              <td>{s.subjectName ?? s.subjectId}</td>
              <td>{s.policyName ?? s.policyId}</td>
              <td>{s.roleName ?? "—"}</td>
              <td className="max-w-[32ch]">{s.reason ?? "—"}</td>
              <td className="tabular-nums whitespace-nowrap">{formatTime(s.startTime)}</td>
              <td className="tabular-nums whitespace-nowrap">{formatTime(s.endTime)}</td>
              <td>
                <Badge tone={SESSION_TONES[s.status] ?? "zinc"}>{label("breakGlassStatus", s.status)}</Badge>
                {s.status === "REVOKED" && <div className="mt-1 text-xs text-ink-3">{s.revokedByName ?? "—"} 종료</div>}
              </td>
              <td>
                {s.status === "ACTIVE" && (
                  <span className="flex justify-end">
                    <RowAction
                      action={endBreakGlassSession}
                      label="끝내기"
                      hidden={{ sessionId: s.sessionId }}
                      confirmMessage={`${s.subjectName ?? s.subjectId} 의 비상 접근을 지금 끝낼까요? 받은 역할이 바로 회수됩니다`}
                    />
                  </span>
                )}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}

function Conditions({ policy }: { policy: BreakGlassPolicy }) {
  const tags = [policy.requireReason && "사유", policy.requireMfa && "2단계 인증", policy.requireApproval && "승인"].filter(Boolean);
  if (tags.length === 0) return <span className="text-ink-3">없음</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {tags.map((t) => (
        <Badge key={String(t)}>{t}</Badge>
      ))}
    </span>
  );
}

function PolicyFields({ policy, groups }: { policy?: BreakGlassPolicy; groups: GroupOption[] }) {
  // 지정해 둔 그룹이 나중에 꺼졌으면 선택지에 없으므로, 저장할 때 풀리지 않게 그 그룹도 보여 준다
  const current = policy?.eligibleGroupId;
  const missing = current != null && !groups.some((g) => g.groupId === current);
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
        <Field label="이름">
          <Input name="policyName" required maxLength={200} defaultValue={policy?.policyName} />
        </Field>
        <Field label="최대 사용 시간 (분)" hint="1~1440분 (24시간)">
          <Input name="maxDurationMinutes" type="number" required min={1} max={1440} defaultValue={policy?.maxDurationMinutes ?? 60} />
        </Field>
        <Field label="쓸 수 있는 사람" hint="그룹을 고르면 그 그룹 구성원만 시작·요청할 수 있습니다">
          <Select name="eligibleGroupId" defaultValue={current ?? ""}>
            <option value="">누구나 (사용 중인 사용자)</option>
            {missing && (
              <option value={current}>
                {policy?.eligibleGroupName ?? current} (꺼진 그룹)
              </option>
            )}
            {groups.map((g) => (
              <option key={g.groupId} value={g.groupId}>
                {g.groupName} ({g.groupCode})
              </option>
            ))}
          </Select>
        </Field>
      </div>
      <div className="flex flex-wrap gap-x-5">
        <Checkbox name="requireReason" label="사유 필수" defaultChecked={policy?.requireReason ?? true} />
        <Checkbox name="requireMfa" label="2단계 인증 로그인 필수" defaultChecked={policy?.requireMfa ?? true} />
        <Checkbox name="requireApproval" label="승인 후 시작" defaultChecked={policy?.requireApproval ?? false} />
      </div>
    </div>
  );
}
