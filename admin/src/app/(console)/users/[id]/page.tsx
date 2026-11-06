import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, SourceStamp, Table, buttonClass } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { RESOURCE, can } from "@/lib/admin-scope";
import { adminScope, formatTime, query, subjectNames } from "@/lib/queries";
import {
  MEMBERSHIP_TYPES,
  type ApiKey,
  type Assignment,
  type LoginAccount,
  type LoginSession,
  type Membership,
  type Organization,
  type Role,
  type RoleHistory,
  type Scope,
  type SubjectMfa,
  type SubjectRisk,
  type User,
} from "@/lib/types";
import {
  addMembership,
  assignRole,
  changeUserActive,
  createLoginAccount,
  issueApiKey,
  leaveMembership,
  removeMfaMethod,
  removePasskey,
  resetPassword,
  retireUser,
  cancelRetire,
  revokeAllSessions,
  revokeApiKey,
  revokeAssignment,
  revokeSession,
  transferPrimary,
  unlockUser,
  updateUser,
} from "../actions";
import { AssignmentUntilForm } from "./assignment-until-form";
import { MembershipJobForm } from "./membership-job-form";

const RISK_TONES: Record<string, "zinc" | "amber" | "red"> = { LOW: "zinc", MEDIUM: "amber", HIGH: "red", CRITICAL: "red" };

/** API 키 리소스 (백엔드 ApiResources.API_KEY) */
const API_KEY_RESOURCE = "iam.authn.apikey";

/** ISO 시각 → datetime-local 입력값 (한국 시각, 분 단위) */
function toKstInput(iso: string | null): string {
  if (!iso) return "";
  return new Date(new Date(iso).getTime() + 9 * 60 * 60 * 1000).toISOString().slice(0, 16);
}


export default function UserDetailPage({ params, searchParams }: PageProps<"/users/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      <UserDetail params={params} searchParams={searchParams} />
    </Suspense>
  );
}

async function UserDetail({ params, searchParams }: { params: PageProps<"/users/[id]">["params"]; searchParams: PageProps<"/users/[id]">["searchParams"] }) {
  const { id } = await params;
  const editing = (await searchParams).edit === "1";
  const here = `/users/${id}`;
  // 조직 단위 관리자처럼 일부 관리 권한만 있으면, 쓸 수 없는 영역(역할·위험·감사)은 부르지 않고 숨긴다
  const scope = await adminScope(here);
  const show = {
    memberships: can(scope, RESOURCE.MEMBERSHIP),
    updateMembership: can(scope, RESOURCE.MEMBERSHIP, "UPDATE"),
    assignments: can(scope, RESOURCE.ASSIGNMENT),
    assignForm: can(scope, RESOURCE.ASSIGNMENT, "CREATE") && can(scope, RESOURCE.ROLE) && can(scope, RESOURCE.SCOPE),
    changeAssignment: can(scope, RESOURCE.ASSIGNMENT, "UPDATE"),
    sessions: can(scope, RESOURCE.SESSION),
    revokeSessions: can(scope, RESOURCE.SESSION, "DELETE"),
    updateUser: can(scope, RESOURCE.USER, "UPDATE"),
    apiKeys: can(scope, API_KEY_RESOURCE),
    issueApiKey: can(scope, API_KEY_RESOURCE, "CREATE"),
    revokeApiKey: can(scope, API_KEY_RESOURCE, "DELETE"),
    history: can(scope, RESOURCE.AUDIT),
    risk: can(scope, RESOURCE.RISK),
  };
  const [user, credential, mfa, apiKeys, memberships, assignments, sessions, history, orgs, roles, scopes, risk] = await Promise.all([
    query<User>(`/api/v1/users/${id}`, here),
    query<LoginAccount | null>(`/api/v1/users/${id}/credential`, here),
    query<SubjectMfa>(`/api/v1/subjects/${id}/mfa`, here),
    show.apiKeys ? query<ApiKey[]>(`/api/v1/subjects/${id}/api-keys`, here) : [],
    show.memberships ? query<Membership[]>(`/api/v1/subjects/${id}/memberships`, here) : [],
    show.assignments ? query<Assignment[]>(`/api/v1/subjects/${id}/assignments`, here) : [],
    show.sessions ? query<LoginSession[]>(`/api/v1/subjects/${id}/sessions`, here) : [],
    show.history ? query<RoleHistory[]>(`/api/v1/audit/role-history/${id}`, here) : [],
    can(scope, RESOURCE.ORGANIZATION) ? query<Organization[]>("/api/v1/organizations", here) : [],
    can(scope, RESOURCE.ROLE) ? query<Role[]>("/api/v1/roles", here) : [],
    can(scope, RESOURCE.SCOPE) ? query<Scope[]>("/api/v1/scopes", here) : [],
    show.risk ? query<SubjectRisk>(`/api/v1/subjects/${id}/risk`, here) : null,
  ]);
  const orgName = new Map(orgs.map((o) => [o.orgId, o.orgName]));
  const actorName = await subjectNames(history.flatMap((h) => (h.changedBy ? [h.changedBy] : [])), here);
  const role = new Map(roles.map((r) => [r.roleId, r]));
  const scopeCode = new Map(scopes.map((s) => [s.scopeId, s.scopeCode]));
  const subject = { subjectId: id };

  return (
    <>
      <PageHeader
        title={user.name}
        description={`${user.userKind === "EXTERNAL" ? `외부 사용자 · ${user.email ?? ""}` : `사번 ${user.empNo ?? "—"}`} · subject ${user.subjectId}`}
      >
        <Link href="/users" className={buttonClass.secondary}>
          목록
        </Link>
      </PageHeader>

      <div className="space-y-6">
        <Card
          title="기본 정보"
          actions={
            <span className="flex items-center gap-2">
              {editing ? (
                <Link href={here} className={buttonClass.row}>
                  닫기
                </Link>
              ) : (
                <Link href={`${here}?edit=1`} className={buttonClass.row}>
                  수정
                </Link>
              )}
              {user.status === "ACTIVE" && (
                <RowAction
                  action={changeUserActive}
                  label="사용 중지"
                  hidden={{ ...subject, active: "false" }}
                  confirmMessage="이 사용자는 로그인할 수 없고 권한 판정에서도 거부됩니다. 사용 중지할까요?"
                />
              )}
              {user.status === "DISABLED" && <RowAction action={changeUserActive} label="다시 사용" tone="neutral" hidden={{ ...subject, active: "true" }} />}
            </span>
          }
        >
          {editing ? (
            <ActionForm key={user.subjectId} action={updateUser} submitLabel="저장">
              <input type="hidden" name="subjectId" value={id} />
              <p className="mb-4 text-ink-3">
                {user.userKind === "EXTERNAL" ? "외부 사용자는 이메일로 식별하므로 비울 수 없습니다" : `사번(${user.empNo ?? "—"})은 바꿀 수 없습니다`}
              </p>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Field label="이름">
                  <Input name="name" required maxLength={200} defaultValue={user.name} />
                </Field>
                <Field label="이메일">
                  <Input name="email" type="email" defaultValue={user.email ?? ""} />
                </Field>
                <Field label="전화">
                  <Input name="phone" maxLength={30} defaultValue={user.phone ?? ""} />
                </Field>
                <Field label="입사일">
                  <Input name="hireDate" type="date" defaultValue={user.hireDate ?? ""} />
                </Field>
              </div>
            </ActionForm>
          ) : (
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
              <dt className="text-ink-3">구분</dt>
              <dd>
                <Badge tone={user.userKind === "EXTERNAL" ? "blue" : "zinc"}>{label("userKind", user.userKind)}</Badge>
              </dd>
              <dt className="text-ink-3">이메일</dt>
              <dd>{user.email ?? "—"}</dd>
              <dt className="text-ink-3">전화</dt>
              <dd className="tabular-nums">{user.phone ?? "—"}</dd>
              <dt className="text-ink-3">상태</dt>
              <dd className="flex items-center gap-2">
                <Badge tone={user.status === "ACTIVE" ? "green" : "red"}>{label("subjectStatus", user.status)}</Badge> <span className="text-ink-2">{label("employment", user.employmentStatus)}</span>
                {credential?.locked && <Badge tone="red">잠김</Badge>}
              </dd>
              <dt className="text-ink-3">입사일</dt>
              <dd className="font-mono tabular-nums">{user.hireDate ?? "—"}</dd>
              {user.retireDate && (
                <>
                  <dt className="text-ink-3">{user.status === "RETIRED" ? "퇴사일" : "퇴사 예정일"}</dt>
                  <dd className="flex items-center gap-2">
                    <span className="font-mono tabular-nums">{user.retireDate}</span>
                    {user.status !== "RETIRED" && (
                      <>
                        <Badge tone="amber">예약</Badge>
                        <RowAction action={cancelRetire} label="예약 취소" tone="neutral" hidden={subject} />
                      </>
                    )}
                  </dd>
                </>
              )}
            </dl>
          )}
          {user.status !== "RETIRED" && (
            <ActionForm
              action={retireUser}
              submitLabel="퇴사 처리"
              variant="danger"
              confirmMessage="오늘 이후 날짜면 그날 자동으로 처리되도록 예약합니다. 처리되면 소속·그룹·역할을 모두 정리하고 세션·토큰·API 키를 회수하며 되돌릴 수 없습니다. 진행할까요?"
              className="mt-4 flex items-end gap-3 border-t border-line pt-4"
            >
              <input type="hidden" name="subjectId" value={id} />
              <Field label="퇴사일" hint="비우면 지금 처리, 오늘 이후면 그날 자동 처리">
                <Input name="retireDate" type="date" />
              </Field>
            </ActionForm>
          )}
        </Card>

        <Card title="로그인 계정">
          {credential ? (
            <>
              <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
                <dt className="text-ink-3">로그인 ID</dt>
                <dd>
                  <Mono>{credential.loginId}</Mono>
                </dd>
                <dt className="text-ink-3">비밀번호 변경</dt>
                <dd className="flex items-center gap-2">
                  <span className="tabular-nums">{formatTime(credential.passwordChangedAt)}</span>
                  {credential.mustChangePassword && <Badge tone="amber">다음 로그인에서 변경</Badge>}
                </dd>
                <dt className="text-ink-3">비밀번호 만료</dt>
                <dd className="tabular-nums">{credential.passwordExpireAt ? formatTime(credential.passwordExpireAt) : "없음"}</dd>
                <dt className="text-ink-3">잠금</dt>
                <dd className="flex items-center gap-2">
                  {credential.locked ? (
                    <>
                      <Badge tone="red">잠김 ({formatTime(credential.lockedUntil)}까지)</Badge>
                      {show.updateUser && <RowAction action={unlockUser} label="잠금 해제" tone="neutral" hidden={subject} />}
                    </>
                  ) : (
                    <span className="text-ink-2">잠기지 않음</span>
                  )}
                </dd>
              </dl>
              {show.updateUser && (
                <ActionForm action={resetPassword} submitLabel="비밀번호 초기화" variant="subtle" resetOnSuccess className="mt-4 flex items-end gap-3 border-t border-line pt-4">
                  <input type="hidden" name="subjectId" value={id} />
                  <Field label="새 비밀번호" hint="잠금도 풀리고, 모든 기기에서 로그아웃되며, 다음 로그인에서 본인이 바꿔야 합니다">
                    <Input name="password" type="password" required autoComplete="new-password" />
                  </Field>
                </ActionForm>
              )}
            </>
          ) : (
            <>
              <p className="text-ink-3">로그인 계정이 없습니다. 이 사용자는 IAM 에 비밀번호로 로그인할 수 없습니다</p>
              {show.updateUser && (
                <ActionForm action={createLoginAccount} submitLabel="로그인 계정 만들기" resetOnSuccess className="mt-4">
                  <input type="hidden" name="subjectId" value={id} />
                  <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                    <Field label="로그인 ID">
                      <Input name="loginId" required maxLength={100} autoComplete="off" />
                    </Field>
                    <Field label="첫 비밀번호" hint="10자 이상, 로그인 ID 포함 불가. 첫 로그인에서 본인이 바꿔야 합니다">
                      <Input name="password" type="password" required minLength={10} maxLength={200} autoComplete="new-password" />
                    </Field>
                  </div>
                </ActionForm>
              )}
            </>
          )}
        </Card>

        <Card title="2단계 인증">
          <p className="mb-4 text-sm text-ink-3">
            기기를 잃어버린 사용자의 인증 수단을 지웁니다. 지운 뒤 다음 로그인은 비밀번호만으로 들어오고 본인이 다시 등록합니다. 이미 로그인한 세션은 그대로이니 필요하면 로그인 세션에서 모두 끊으세요
          </p>
          <Table headers={["종류", "이름", "등록", "마지막 사용", ""]} empty={mfa.methods.length + mfa.passkeys.length === 0} emptyText="등록한 2단계 인증 수단이 없습니다">
            {mfa.methods.map((m, i) => (
              <tr key={`m-${m.methodId}`}>
                <td>인증 앱</td>
                <td className="font-medium">인증 앱 {i + 1}</td>
                <td>{formatTime(m.registeredAt)}</td>
                <td>{formatTime(m.lastUsedAt)}</td>
                <td className="text-right">
                  {show.updateUser && (
                    <RowAction
                      action={removeMfaMethod}
                      label="초기화"
                      hidden={{ ...subject, methodId: m.methodId }}
                      confirmMessage="이 인증 앱을 지울까요? 그 앱의 코드로는 더 로그인할 수 없고, 본인이 다시 등록해야 합니다"
                    />
                  )}
                </td>
              </tr>
            ))}
            {mfa.passkeys.map((p) => (
              <tr key={`p-${p.credentialId}`}>
                <td>패스키</td>
                <td className="font-medium">{p.label}</td>
                <td>{formatTime(p.createdAt)}</td>
                <td>{formatTime(p.lastUsedAt)}</td>
                <td className="text-right">
                  {show.updateUser && (
                    <RowAction
                      action={removePasskey}
                      label="초기화"
                      hidden={{ ...subject, credentialId: p.credentialId }}
                      confirmMessage="이 패스키를 지울까요? 그 기기로는 패스키 로그인을 할 수 없습니다"
                    />
                  )}
                </td>
              </tr>
            ))}
          </Table>
        </Card>

        {show.memberships && (
          <Card title="소속">
            <Table headers={["조직", "유형", "직위", "직급", "관리자", "시작", ""]} empty={memberships.length === 0}>
              {memberships.map((m) => (
                <tr key={m.membershipId}>
                  <td>
                    <Link href={`/organizations/${m.orgId}`} className="font-medium text-ink hover:text-accent">
                      {orgName.get(m.orgId) ?? m.orgId}
                    </Link>
                  </td>
                  <td>{label("membership", m.membershipType)}</td>
                  <td>{m.jobTitle ?? "—"}</td>
                  <td>{m.jobGrade ?? "—"}</td>
                  <td>{m.isManager ? "예" : ""}</td>
                  <td>{formatTime(m.validFrom)}</td>
                  <td>
                    <span className="flex flex-wrap items-center justify-end gap-2">
                      {show.updateMembership && <MembershipJobForm membership={m} from="user" />}
                      <RowAction action={leaveMembership} label="종료" hidden={{ ...subject, membershipId: m.membershipId }} confirmMessage="이 소속을 종료할까요? 조직 역할도 함께 회수됩니다." />
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
            <div className="mt-4 grid gap-6 md:grid-cols-2">
              <ActionForm action={addMembership} submitLabel="소속 추가" resetOnSuccess>
                <input type="hidden" name="subjectId" value={id} />
                <MembershipFields orgs={orgs} orgField="orgId" withType />
              </ActionForm>
              <ActionForm action={transferPrimary} submitLabel="주 소속 이동 (전적·전보)" variant="subtle" confirmMessage="주 소속을 옮길까요? 법인이 바뀌면 이전 법인 권한이 회수됩니다.">
                <input type="hidden" name="subjectId" value={id} />
                <MembershipFields orgs={orgs} orgField="newOrgId" />
              </ActionForm>
            </div>
          </Card>
        )}

        {show.assignments && (
          <Card title="보유 역할">
            <Table headers={["역할", "범위", "출처", "만료", "상태", ""]} empty={assignments.length === 0}>
              {assignments.map((a) => (
                <tr key={a.assignmentId}>
                  <td>
                    <Link href={`/roles/${a.roleId}`} className="font-medium text-ink hover:text-accent">
                      {role.get(a.roleId)?.roleName ?? a.roleId}
                    </Link>
                  </td>
                  <td>
                    <Mono>{scopeCode.get(a.scopeId) ?? a.scopeId}</Mono>
                  </td>
                  <td>
                    <SourceStamp source={a.sourceType} />
                  </td>
                  <td>
                    {a.sourceType === "DIRECT" && show.changeAssignment ? (
                      <AssignmentUntilForm subjectId={id} assignmentId={a.assignmentId} current={toKstInput(a.validUntil)} />
                    ) : (
                      formatTime(a.validUntil)
                    )}
                  </td>
                  <td>{a.reviewRequired && <Badge tone="amber">재검토 필요</Badge>}</td>
                  <td>
                    {a.sourceType === "DIRECT" && (
                      <RowAction action={revokeAssignment} label="회수" hidden={{ ...subject, assignmentId: a.assignmentId }} confirmMessage="이 역할을 회수할까요?" />
                    )}
                  </td>
                </tr>
              ))}
            </Table>
            {show.assignForm && (
              <ActionForm action={assignRole} submitLabel="역할 부여" resetOnSuccess className="mt-4">
                <input type="hidden" name="subjectId" value={id} />
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  <Field label="역할">
                    <Select name="roleId" required>
                      {roles.filter((r) => r.isActive).map((r) => (
                        <option key={r.roleId} value={r.roleId}>
                          {r.roleName} ({r.roleCode})
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="범위">
                    <Select name="scopeId">
                      <option value="">전체</option>
                      {scopes.filter((s) => s.scopeType !== "GLOBAL").map((s) => (
                        <option key={s.scopeId} value={s.scopeId}>
                          {s.scopeName} ({s.scopeCode})
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="만료 (선택)">
                    <Input name="validUntil" type="datetime-local" />
                  </Field>
                  <Field label="사유">
                    <Input name="reason" maxLength={1000} />
                  </Field>
                </div>
              </ActionForm>
            )}
          </Card>
        )}

        {show.sessions && (
          <Card
            title="로그인 세션"
            actions={
              // 세션이 없어도 남은 토큰을 회수할 수 있게 늘 둔다
              show.revokeSessions && (
                <RowAction
                  action={revokeAllSessions}
                  label="모든 세션 끊기"
                  hidden={subject}
                  confirmMessage="이 사용자의 모든 로그인 세션을 끝내고 발급한 토큰을 회수할까요? 모든 기기와 연결된 시스템에서 다시 로그인해야 합니다"
                />
              )
            }
          >
            <Table headers={["로그인", "인증 수준", "IP", "만료", ""]} empty={sessions.length === 0}>
              {sessions.map((s) => (
                <tr key={s.sessionId}>
                  <td>{formatTime(s.loginAt)}</td>
                  <td>{label("authLevel", s.authenticationLevel)}</td>
                  <td>
                    <Mono>{s.ipAddress ?? "—"}</Mono>
                  </td>
                  <td>{formatTime(s.expireAt)}</td>
                  <td>
                    <RowAction action={revokeSession} label="강제 종료" hidden={{ ...subject, sessionId: s.sessionId }} confirmMessage="이 로그인 세션을 종료할까요?" />
                  </td>
                </tr>
              ))}
            </Table>
          </Card>
        )}

        {show.apiKeys && (
          <Card title="API 키">
            <Table headers={["이름", "발급", "만료", "마지막 사용", "상태", ""]} empty={apiKeys.length === 0} emptyText="발급한 API 키가 없습니다">
              {apiKeys.map((k) => (
                <tr key={k.apiKeyId}>
                  <td className="font-medium">{k.keyName}</td>
                  <td>{formatTime(k.issuedAt)}</td>
                  <td>{k.expireAt ? formatTime(k.expireAt) : "없음"}</td>
                  <td>{formatTime(k.lastUsedAt)}</td>
                  <td>
                    {k.revoked ? (
                      <>
                        <Badge tone="red">폐기</Badge>
                        {k.revokedAt && <div className="mt-1 text-xs text-ink-3 tabular-nums">{formatTime(k.revokedAt)}</div>}
                      </>
                    ) : k.expireAt && new Date(k.expireAt) <= new Date() ? (
                      <Badge tone="zinc">만료</Badge>
                    ) : (
                      <Badge tone="green">사용 중</Badge>
                    )}
                  </td>
                  <td className="text-right">
                    {!k.revoked && show.revokeApiKey && (
                      <RowAction
                        action={revokeApiKey}
                        label="폐기"
                        hidden={{ ...subject, apiKeyId: k.apiKeyId }}
                        confirmMessage="이 API 키를 폐기할까요? 이 키를 쓰는 연동은 바로 실패하며 되돌릴 수 없습니다"
                      />
                    )}
                  </td>
                </tr>
              ))}
            </Table>
            {show.issueApiKey && (
              <ActionForm action={issueApiKey} submitLabel="API 키 발급" resetOnSuccess className="mt-4 border-t border-line pt-4">
                <input type="hidden" name="subjectId" value={id} />
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <Field label="이름" hint="어디에 쓰는 키인지 알아볼 수 있게">
                    <Input name="keyName" required maxLength={200} />
                  </Field>
                  <Field label="만료 (선택)" hint="비우면 기한 없음">
                    <Input name="expireAt" type="datetime-local" />
                  </Field>
                </div>
              </ActionForm>
            )}
          </Card>
        )}

        {risk && (
          <Card title="위험 평가" actions={<Link href="/risk-policies" className="text-ink-2 hover:text-ink">위험 정책</Link>}>
            <Table headers={["시각", "점수", "수준", "결과", "접근 요청"]} empty={risk.assessments.length === 0} emptyText="위험 신호가 잡힌 적이 없습니다">
              {risk.assessments.map((a) => (
                <tr key={a.assessmentId}>
                  <td>{formatTime(a.assessedAt)}</td>
                  <td className="tabular-nums">{a.riskScore}</td>
                  <td>
                    <Badge tone={RISK_TONES[a.riskLevel] ?? "zinc"}>{label("risk", a.riskLevel)}</Badge>
                  </td>
                  <td>{label("riskAction", a.decision)}</td>
                  <td>{a.requestId ? <Mono>{a.requestId}</Mono> : "—"}</td>
                </tr>
              ))}
            </Table>
            {risk.signals.length > 0 && (
              <>
                <h3 className="mt-5 mb-2 text-[13px] font-medium text-ink-2">잡힌 신호</h3>
                <Table headers={["시각", "신호", "점수", "근거"]}>
                  {risk.signals.map((s) => (
                    <tr key={s.riskSignalId}>
                      <td>{formatTime(s.detectedAt)}</td>
                      <td>{label("riskSignal", s.signalType)}</td>
                      <td className="tabular-nums">{s.riskScore}</td>
                      <td>
                        <Mono>{s.details ?? "—"}</Mono>
                      </td>
                    </tr>
                  ))}
                </Table>
              </>
            )}
          </Card>
        )}

        {show.history && (
          <Card title="역할 변경 이력">
            <Table headers={["시각", "변경", "역할", "사유", "처리자"]} empty={history.length === 0}>
              {history.map((h) => (
                <tr key={h.historyId}>
                  <td>{formatTime(h.changedAt)}</td>
                  <td>{label("changeType", h.changeType)}</td>
                  <td>{role.get(h.roleId)?.roleName ?? h.roleId}</td>
                  <td>{h.reason ?? "—"}</td>
                  <td>{h.changedBy ? (actorName.get(h.changedBy) ?? h.changedBy) : "시스템"}</td>
                </tr>
              ))}
            </Table>
          </Card>
        )}
      </div>
    </>
  );
}

function MembershipFields({ orgs, orgField, withType = false }: { orgs: Organization[]; orgField: string; withType?: boolean }) {
  return (
    <div className="grid grid-cols-2 gap-3">
      <Field label="조직">
        <Select name={orgField} required>
          {orgs.map((o) => (
            <option key={o.orgId} value={o.orgId}>
              {"　".repeat(o.orgLevel - 1)}
              {o.orgName}
            </option>
          ))}
        </Select>
      </Field>
      {withType ? (
        <Field label="유형">
          <Select name="membershipType">
            <Options values={MEMBERSHIP_TYPES} labels={LABELS.membership} />
          </Select>
        </Field>
      ) : (
        <span />
      )}
      <Field label="직위">
        <Input name="jobTitle" maxLength={100} />
      </Field>
      <Field label="직급">
        <Input name="jobGrade" maxLength={100} />
      </Field>
      <Checkbox name="isManager" label="조직 관리자" />
    </div>
  );
}
