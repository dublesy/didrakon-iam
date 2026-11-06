import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { RESOURCE, can } from "@/lib/admin-scope";
import { adminScope, formatTime, query, subjectNames } from "@/lib/queries";
import { ORG_TYPES, type Membership, type Organization, type OrganizationRole, type Role, type Scope } from "@/lib/types";
import { changeOrganizationActive, createOrganizationRole, deactivateOrganizationRole, moveOrganization, updateOrganization } from "../actions";
import { OrgOptions } from "../org-options";
import { MembershipJobForm } from "../../users/[id]/membership-job-form";


export default function OrganizationDetailPage({ params, searchParams }: PageProps<"/organizations/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      <OrganizationDetail params={params} searchParams={searchParams} />
    </Suspense>
  );
}

async function OrganizationDetail({
  params,
  searchParams,
}: {
  params: PageProps<"/organizations/[id]">["params"];
  searchParams: PageProps<"/organizations/[id]">["searchParams"];
}) {
  const { id } = await params;
  const editing = (await searchParams).edit === "1";
  const here = `/organizations/${id}`;
  // 조직 역할 규칙은 역할 할당 권한이 있을 때만 (조직 단위 관리자는 역할을 줄 수 없다)
  const scope = await adminScope(here);
  const showRules = can(scope, RESOURCE.ASSIGNMENT);
  const canUpdateMembership = can(scope, RESOURCE.MEMBERSHIP, "UPDATE");
  const [org, members, rules, orgs, roles, scopes] = await Promise.all([
    query<Organization>(`/api/v1/organizations/${id}`, here),
    can(scope, RESOURCE.MEMBERSHIP) ? query<Membership[]>(`/api/v1/organizations/${id}/members`, here) : [],
    showRules ? query<OrganizationRole[]>(`/api/v1/organizations/${id}/roles`, here) : [],
    query<Organization[]>("/api/v1/organizations", here),
    can(scope, RESOURCE.ROLE) ? query<Role[]>("/api/v1/roles", here) : [],
    can(scope, RESOURCE.SCOPE) ? query<Scope[]>("/api/v1/scopes", here) : [],
  ]);
  const names = await subjectNames(members.map((m) => m.subjectId), here);
  const orgName = new Map(orgs.map((o) => [o.orgId, o.orgName]));
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  const scopeCode = new Map(scopes.map((s) => [s.scopeId, s.scopeCode]));
  const parentLink = (orgId: number | null) =>
    orgId === null ? (
      "—"
    ) : (
      <Link href={`/organizations/${orgId}`} className="font-medium text-ink hover:text-accent">
        {orgName.get(orgId) ?? orgId}
      </Link>
    );

  return (
    <>
      <PageHeader title={org.orgName} description={`코드 ${org.orgCode} · ${label("orgType", org.orgType)}`}>
        <Link href="/organizations" className={buttonClass.secondary}>
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
              {org.isActive ? (
                <RowAction
                  action={changeOrganizationActive}
                  label="조직 닫기"
                  hidden={{ orgId: id, active: "false" }}
                  confirmMessage={`'${org.orgName}' 조직을 닫을까요? 구성원이나 열린 하위 조직이 있으면 닫을 수 없습니다`}
                />
              ) : (
                <RowAction action={changeOrganizationActive} label="다시 열기" tone="neutral" hidden={{ orgId: id, active: "true" }} />
              )}
            </span>
          }
        >
          {editing && (
            <ActionForm key={org.orgId} action={updateOrganization} submitLabel="저장" className="mb-5 border-b border-line pb-5">
              <input type="hidden" name="orgId" value={id} />
              <p className="mb-4 text-ink-3">코드({org.orgCode})는 바꿀 수 없습니다</p>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Field label="이름">
                  <Input name="orgName" required maxLength={200} defaultValue={org.orgName} />
                </Field>
                <Field label="유형">
                  <Select name="orgType" defaultValue={org.orgType}>
                    <Options values={ORG_TYPES} labels={LABELS.orgType} />
                  </Select>
                </Field>
              </div>
            </ActionForm>
          )}
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
            <dt className="text-ink-3">상태</dt>
            <dd>{org.isActive ? <Badge tone="green">열림</Badge> : <Badge>닫힘</Badge>}</dd>
            <dt className="text-ink-3">상위 조직</dt>
            <dd>{parentLink(org.parentOrgId)}</dd>
            <dt className="text-ink-3">소속 법인</dt>
            <dd>{parentLink(org.companyOrgId)}</dd>
            <dt className="text-ink-3">레벨</dt>
            <dd className="tabular-nums">{org.orgLevel}</dd>
          </dl>
          <ActionForm
            action={moveOrganization}
            submitLabel="조직 이동"
            variant="subtle"
            confirmMessage="이 조직을 옮길까요? 하위 조직도 함께 옮겨집니다."
            className="mt-4 flex items-end gap-3"
          >
            <input type="hidden" name="orgId" value={id} />
            <Field label="새 상위 조직">
              <Select name="newParentOrgId" required>
                <OrgOptions orgs={orgs.filter((o) => o.orgId !== org.orgId)} />
              </Select>
            </Field>
          </ActionForm>
        </Card>

        <Card title="구성원">
          <Table headers={["이름", "유형", "직위", "직급", "관리자", "시작", ""]} empty={members.length === 0}>
            {members.map((m) => (
              <tr key={m.membershipId}>
                <td>
                  <Link href={`/users/${m.subjectId}`} className="font-medium text-ink hover:text-accent">
                    {names.get(m.subjectId) ?? m.subjectId}
                  </Link>
                </td>
                <td>{label("membership", m.membershipType)}</td>
                <td>{m.jobTitle ?? "—"}</td>
                <td>{m.jobGrade ?? "—"}</td>
                <td>{m.isManager ? "예" : ""}</td>
                <td>{formatTime(m.validFrom)}</td>
                <td className="text-right">{canUpdateMembership && <MembershipJobForm membership={m} from="org" />}</td>
              </tr>
            ))}
          </Table>
        </Card>

        {showRules && (
          <Card title="조직 역할 규칙">
            <p className="mb-4 text-ink-3">이 조직 구성원에게 자동으로 주는 역할</p>
            <Table headers={["역할", "범위", "하위 조직 포함", "상태", ""]} empty={rules.length === 0}>
              {rules.map((r) => (
                <tr key={r.orgRoleId}>
                  <td>{roleName.get(r.roleId) ?? r.roleId}</td>
                  <td>
                    <Mono>{scopeCode.get(r.scopeId) ?? r.scopeId}</Mono>
                  </td>
                  <td>{r.applyToDescendants ? "예" : ""}</td>
                  <td>
                    <Badge tone={r.isActive ? "green" : "zinc"}>{r.isActive ? "활성" : "비활성"}</Badge>
                  </td>
                  <td>
                    {r.isActive && (
                      <RowAction
                        action={deactivateOrganizationRole}
                        label="비활성화"
                        hidden={{ orgId: id, orgRoleId: r.orgRoleId }}
                        confirmMessage="이 규칙을 비활성화할까요? 규칙으로 받은 역할이 회수됩니다."
                      />
                    )}
                  </td>
                </tr>
              ))}
            </Table>
            <ActionForm action={createOrganizationRole} submitLabel="규칙 추가" resetOnSuccess className="mt-4">
              <input type="hidden" name="orgId" value={id} />
              <div className="grid grid-cols-2 items-end gap-3 md:grid-cols-3">
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
                <Checkbox name="applyToDescendants" label="하위 조직에도 적용" />
              </div>
            </ActionForm>
          </Card>
        )}
      </div>
    </>
  );
}
