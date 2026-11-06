import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import { type Permission, type PolicyDetail, type PolicyRule, type Resource, type Role } from "@/lib/types";
import { activateVersion, addPolicyException, addPolicyTarget, changePolicyActive, endPolicyException, removePolicyTarget, updatePolicy } from "../actions";
import { RuleEditor } from "../rule-editor";
import { TargetFields } from "../target-fields";

/** IamBootstrap.MFA_POLICY */
const SYSTEM_MFA_POLICY = "IAM_ADMIN_API_MFA";

/** 만료가 없거나 아직 오지 않은 예외 */
function isOpen(validUntil: string | null): boolean {
  return validUntil === null || new Date(validUntil).getTime() > Date.now();
}

const STATUS_TONES: Record<string, "green" | "amber" | "zinc"> = { ACTIVE: "green", DRAFT: "amber", RETIRED: "zinc" };

export default function PolicyDetailPage({ params }: PageProps<"/policies/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      <PolicyDetailView params={params} />
    </Suspense>
  );
}

async function PolicyDetailView({ params }: { params: PageProps<"/policies/[id]">["params"] }) {
  const { id } = await params;
  const here = `/policies/${id}`;
  const [detail, roles, resources, permissions] = await Promise.all([
    query<PolicyDetail>(`/api/v1/policies/${id}`, here),
    query<Role[]>("/api/v1/roles", here),
    query<Resource[]>("/api/v1/resources", here),
    query<Permission[]>("/api/v1/permissions", here),
  ]);
  const { policy, targets, exceptions } = detail;
  const versions = [...detail.versions].sort((a, b) => b.version - a.version);
  const names = await subjectNames(exceptions.flatMap((e) => (e.subjectId === null ? [] : [e.subjectId])), here);
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  const resourceName = new Map(resources.map((r) => [r.resourceId, r.resourceName]));
  const permissionName = new Map(permissions.map((p) => [p.permissionId, p.permissionName]));
  const targetSpecs = targets.map((t) =>
    t.roleId !== null ? { roleId: t.roleId } : t.resourceId !== null ? { resourceId: t.resourceId } : { permissionId: t.permissionId },
  );
  const targetOptions = {
    role: roles.map((r) => ({ id: r.roleId, label: `${r.roleName} (${r.roleCode})` })),
    resource: resources.map((r) => ({ id: r.resourceId, label: `${r.resourceName} (${r.resourceKey})` })),
    permission: permissions.map((p) => ({ id: p.permissionId, label: `${p.permissionName} (${p.permissionCode})` })),
  };
  // 관리 API MFA 정책은 설정으로만 관리한다 (서버도 끄기·대상·규칙 변경을 거부한다)
  const locked = policy.policyCode === SYSTEM_MFA_POLICY;
  // 예외가 끝났는지는 현재 시각 기준이라 요청 시점에 계산한다
  await connection();

  return (
    <>
      <PageHeader
        title={policy.policyName}
        description={`${label("policyType", policy.policyType)} · ${label("policyEffect", policy.effect)}${policy.isActive ? "" : " · 꺼짐"}`}
      >
        <Mono>{policy.policyCode}</Mono>
        <Link href="/policies" className={buttonClass.secondary}>
          목록
        </Link>
      </PageHeader>

      <div className="space-y-6">
        <Card
          title="기본 정보"
          actions={
            !locked && <RowAction
              action={changePolicyActive}
              label={policy.isActive ? "끄기" : "켜기"}
              tone={policy.isActive ? "danger" : "neutral"}
              hidden={{ policyId: policy.policyId, active: String(!policy.isActive) }}
              confirmMessage={policy.isActive ? "이 정책이 판정에서 빠집니다. 끌까요?" : undefined}
            />
          }
        >
          <p className="mb-4 text-ink-3">
            {locked
              ? "관리 API 에 2단계 인증을 요구하는 기본 정책입니다. 끄기·대상·규칙은 서버 설정(iam.bootstrap.require-mfa-for-admin)으로 관리하고 여기서는 이름과 우선순위만 바꿉니다"
              : "유형과 효과는 바꿀 수 없습니다. 규칙은 새 버전으로 바꿉니다"}
          </p>
          <ActionForm key={`${policy.policyName}-${policy.priority}`} action={updatePolicy} submitLabel="저장">
            <input type="hidden" name="policyId" value={policy.policyId} />
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="이름">
                <Input name="policyName" required maxLength={200} defaultValue={policy.policyName} />
              </Field>
              <Field label="우선순위">
                <Input name="priority" type="number" required defaultValue={policy.priority} />
              </Field>
            </div>
          </ActionForm>
        </Card>

        <Card title="대상">
          <p className="mb-4 text-ink-3">대상을 바꾸면 다음 판정부터 적용됩니다. 대상은 하나 이상 있어야 합니다</p>
          <div className={locked ? "hidden" : "mb-4"}>
            <AddPanel label="대상 추가">
              <ActionForm action={addPolicyTarget} submitLabel="추가">
                <input type="hidden" name="policyId" value={policy.policyId} />
                <input type="hidden" name="targets" value={JSON.stringify(targetSpecs)} />
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  <TargetFields options={targetOptions} />
                </div>
              </ActionForm>
            </AddPanel>
          </div>
          <Table headers={["종류", "이름", ""]} empty={targets.length === 0}>
            {targets.map((t, i) => (
              <tr key={t.policyTargetId}>
                {t.roleId !== null ? (
                  <>
                    <td>역할</td>
                    <td>{roleName.get(t.roleId) ?? t.roleId}</td>
                  </>
                ) : t.resourceId !== null ? (
                  <>
                    <td>리소스</td>
                    <td>{resourceName.get(t.resourceId) ?? t.resourceId}</td>
                  </>
                ) : (
                  <>
                    <td>권한</td>
                    <td>{t.permissionId === null ? "—" : (permissionName.get(t.permissionId) ?? t.permissionId)}</td>
                  </>
                )}
                <td className="text-right">
                  {!locked && targets.length > 1 && (
                    <RowAction
                      action={removePolicyTarget}
                      label="빼기"
                      hidden={{ policyId: policy.policyId, targets: JSON.stringify(targetSpecs.filter((_, j) => j !== i)) }}
                      confirmMessage="이 대상을 빼면 다음 판정부터 정책이 걸리지 않습니다. 뺄까요?"
                    />
                  )}
                </td>
              </tr>
            ))}
          </Table>
        </Card>

        <Card title="버전">
          <p className="mb-4 text-ink-3">같은 그룹은 AND, 그룹끼리는 OR 로 묶입니다</p>
          {versions.length === 0 && <p className="py-6 text-center text-ink-3">아직 버전이 없습니다</p>}
          <div className="space-y-4">
            {versions.map((v) => (
              <div key={v.policyVersionId} className="rounded-lg border border-line p-4">
                <div className="mb-3 flex flex-wrap items-center gap-2">
                  <span className="font-mono font-semibold text-ink">v{v.version}</span>
                  <Badge tone={STATUS_TONES[v.status] ?? "zinc"}>{label("versionStatus", v.status)}</Badge>
                  <span className="font-mono text-xs text-ink-3 tabular-nums">{formatTime(v.createdAt)}</span>
                  {v.changeReason && <span className="text-ink-2">· {v.changeReason}</span>}
                </div>
                <RuleGroups rules={v.rules} />
                {v.status === "DRAFT" && (
                  <ActionForm action={activateVersion} submitLabel="활성화" variant="subtle" confirmMessage={`v${v.version} 을 활성화할까요? 지금 활성 버전은 대체됩니다.`}>
                    <input type="hidden" name="policyId" value={policy.policyId} />
                    <input type="hidden" name="versionId" value={v.policyVersionId} />
                  </ActionForm>
                )}
              </div>
            ))}
          </div>
        </Card>

        {!locked && (
          <AddPanel label="새 버전 만들기">
            <RuleHelp />
            <RuleEditor policyId={policy.policyId} />
          </AddPanel>
        )}

        <Card title="예외">
          <div className="mb-4">
            <AddPanel label="예외 추가">
              <ActionForm action={addPolicyException} submitLabel="추가" resetOnSuccess>
                <input type="hidden" name="policyId" value={policy.policyId} />
                <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                  <Field label="대상 subject ID (선택)">
                    <Input name="subjectId" type="number" min={1} />
                  </Field>
                  <Field label="리소스 (선택)">
                    <Select name="resourceId">
                      <option value="">—</option>
                      {resources.map((r) => (
                        <option key={r.resourceId} value={r.resourceId}>
                          {r.resourceName} ({r.resourceKey})
                        </option>
                      ))}
                    </Select>
                  </Field>
                  <Field label="사유">
                    <Input name="reason" required maxLength={1000} />
                  </Field>
                  <Field label="만료 (선택)">
                    <Input name="validUntil" type="datetime-local" />
                  </Field>
                </div>
              </ActionForm>
            </AddPanel>
          </div>
          <Table headers={["대상자", "리소스", "사유", "시작", "만료", ""]} empty={exceptions.length === 0}>
            {exceptions.map((e) => {
              const open = isOpen(e.validUntil);
              return (
                <tr key={e.exceptionId} className={open ? undefined : "text-ink-3"}>
                  <td>{e.subjectId === null ? "—" : (names.get(e.subjectId) ?? e.subjectId)}</td>
                  <td>{e.resourceId === null ? "—" : (resourceName.get(e.resourceId) ?? e.resourceId)}</td>
                  <td>{e.reason}</td>
                  <td>{formatTime(e.validFrom)}</td>
                  <td>{formatTime(e.validUntil)}</td>
                  <td className="text-right">
                    {open ? (
                      <RowAction
                        action={endPolicyException}
                        label="끝내기"
                        hidden={{ policyId: policy.policyId, exceptionId: e.exceptionId }}
                        confirmMessage="이 예외를 지금 끝낼까요?"
                      />
                    ) : (
                      <span className="whitespace-nowrap text-xs">끝남</span>
                    )}
                  </td>
                </tr>
              );
            })}
          </Table>
        </Card>
      </div>
    </>
  );
}

/** 규칙을 그룹별로 묶어 보여준다 */
function RuleGroups({ rules }: { rules: PolicyRule[] }) {
  if (rules.length === 0) return <p className="text-ink-3">규칙이 없습니다</p>;
  const groups = Map.groupBy(rules, (r) => r.ruleGroup);
  return (
    <div className="space-y-2">
      {[...groups.entries()]
        .sort(([a], [b]) => a - b)
        .map(([group, groupRules]) => (
          <div key={group}>
            <span className="text-xs text-ink-3">그룹 {group}</span>
            <ul className="mt-1 ml-4 list-disc text-ink-3">
              {[...groupRules]
                .sort((a, b) => a.ruleOrder - b.ruleOrder)
                .map((r) => (
                  <li key={`${r.ruleOrder}-${r.attributeName}`}>
                    <Mono>
                      {r.attributeSource}.{r.attributeName} {r.operator} {r.attributeValue ?? ""}
                    </Mono>
                  </li>
                ))}
            </ul>
          </div>
        ))}
    </div>
  );
}

function RuleHelp() {
  return (
    <div className="mb-4 rounded-lg bg-panel p-4 text-xs text-ink-2">
      <p className="mb-2">효과가 조건부 허용이면 조건을 만족할 때만 허용합니다. 값은 JSON 으로 씁니다. EXISTS 는 값을 비웁니다.</p>
      <dl className="grid grid-cols-[max-content_1fr] gap-x-3 gap-y-0.5">
        <dt className="font-medium text-ink">주체</dt>
        <dd className="font-mono">subjectType, userKind, status, employmentStatus, orgIds, companyOrgIds, primaryOrgId, primaryCompanyOrgId, isManager, roleCodes</dd>
        <dt className="font-medium text-ink">리소스</dt>
        <dd className="font-mono">resourceId, resourceKey, resourceType, sensitivity, clientId</dd>
        <dt className="font-medium text-ink">요청 상황</dt>
        <dd>호출 시스템이 넘긴 값 + orgId</dd>
        <dt className="font-medium text-ink">세션</dt>
        <dd>amr 등</dd>
        <dt className="font-medium text-ink">관계</dt>
        <dd>관계 코드 (예: OWNS) 를 EXISTS 로 검사</dd>
      </dl>
    </div>
  );
}
