import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, Options, PageHeader, Select, Table } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { RESOURCE, can } from "@/lib/admin-scope";
import { adminScope, query } from "@/lib/queries";
import { ORG_TYPES, type Organization } from "@/lib/types";
import { createOrganization } from "./actions";
import { OrgOptions } from "./org-options";

export default function OrganizationsPage() {
  return (
    <>
      <PageHeader title="조직" description="그룹·법인·부서 트리. 조직 역할 규칙은 상세에서 관리합니다." />
      <Suspense fallback={<Loading />}>
        <OrganizationList />
      </Suspense>
    </>
  );
}

/** 조직 단위 관리자는 범위 안 조직만 받는다. 상위 조직이 빠질 수 있으므로 들여쓰기는 받은 조직 중 가장 높은 레벨을 기준으로 한다 */
async function OrganizationList() {
  const [orgs, scope] = await Promise.all([
    query<Organization[]>("/api/v1/organizations", "/organizations"),
    adminScope("/organizations"),
  ]);
  const topLevel = Math.min(...orgs.map((o) => o.orgLevel), Number.MAX_SAFE_INTEGER);

  return (
    <div className="space-y-6">
      {can(scope, RESOURCE.ORGANIZATION, "CREATE") && (
        <AddPanel label="조직 추가">
          <ActionForm action={createOrganization} submitLabel="만들기" resetOnSuccess>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="코드">
                <Input name="orgCode" required maxLength={100} />
              </Field>
              <Field label="이름">
                <Input name="orgName" required maxLength={200} />
              </Field>
              <Field label="유형">
                <Select name="orgType">
                  <Options values={ORG_TYPES} labels={LABELS.orgType} />
                </Select>
              </Field>
              <Field label="상위 조직">
                <Select name="parentOrgId">
                  <option value="">없음 (최상위)</option>
                  <OrgOptions orgs={orgs} />
                </Select>
              </Field>
            </div>
          </ActionForm>
        </AddPanel>
      )}
      <Card>
        <Table headers={["조직", "코드", "유형", "레벨"]} empty={orgs.length === 0}>
          {orgs.map((o) => (
            <tr key={o.orgId} className={o.isActive ? undefined : "text-ink-3"}>
              <td style={{ paddingLeft: `${(o.orgLevel - topLevel) * 1.25 + 0.5}rem` }}>
                <span className="inline-flex items-center gap-2">
                  <Link href={`/organizations/${o.orgId}`} className={`font-medium hover:text-accent ${o.isActive ? "text-ink" : "text-ink-3"}`}>
                    {o.orgName}
                  </Link>
                  {!o.isActive && <Badge>닫힘</Badge>}
                </span>
              </td>
              <td>
                <Mono>{o.orgCode}</Mono>
              </td>
              <td>{label("orgType", o.orgType)}</td>
              <td className="tabular-nums text-ink-2">{o.orgLevel}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
