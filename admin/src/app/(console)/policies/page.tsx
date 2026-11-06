import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, Options, PageHeader, Select, Table } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { query } from "@/lib/queries";
import { POLICY_EFFECTS, POLICY_TYPES, type Permission, type Policy, type Resource, type Role } from "@/lib/types";
import { createPolicy } from "./actions";
import { TargetFields } from "./target-fields";

export default function PoliciesPage() {
  return (
    <>
      <PageHeader title="정책(ABAC)" description="역할·리소스·권한에 속성 조건을 더합니다. 규칙은 상세 화면에서 버전으로 만들고 활성화합니다" />
      <Suspense fallback={<Loading />}>
        <PolicyList />
      </Suspense>
    </>
  );
}

async function PolicyList() {
  const here = "/policies";
  const [policies, roles, resources, permissions] = await Promise.all([
    query<Policy[]>("/api/v1/policies", here),
    query<Role[]>("/api/v1/roles", here),
    query<Resource[]>("/api/v1/resources", here),
    query<Permission[]>("/api/v1/permissions", here),
  ]);

  return (
    <div className="space-y-6">
      <AddPanel label="정책 추가">
        <ActionForm action={createPolicy} submitLabel="만들기" resetOnSuccess>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Field label="코드">
              <Input name="policyCode" required maxLength={100} />
            </Field>
            <Field label="이름">
              <Input name="policyName" required maxLength={200} />
            </Field>
            <Field label="유형">
              <Select name="policyType">
                <Options values={POLICY_TYPES} labels={LABELS.policyType} />
              </Select>
            </Field>
            <Field label="효과" hint="조건부 허용: 조건을 만족할 때만 허용">
              <Select name="effect">
                <Options values={POLICY_EFFECTS} labels={LABELS.policyEffect} />
              </Select>
            </Field>
            <Field label="우선순위">
              <Input name="priority" type="number" defaultValue={0} />
            </Field>
            <TargetFields
              options={{
                role: roles.map((r) => ({ id: r.roleId, label: `${r.roleName} (${r.roleCode})` })),
                resource: resources.map((r) => ({ id: r.resourceId, label: `${r.resourceName} (${r.resourceKey})` })),
                permission: permissions.map((p) => ({ id: p.permissionId, label: `${p.permissionName} (${p.permissionCode})` })),
              }}
            />
          </div>
        </ActionForm>
      </AddPanel>

      <Card>
        <Table headers={["코드", "이름", "유형", "효과", "상태"]} empty={policies.length === 0}>
          {policies.map((p) => (
            <tr key={p.policyId} className={p.isActive ? undefined : "text-ink-3"}>
              <td>
                <Mono>{p.policyCode}</Mono>
              </td>
              <td>
                <Link href={`/policies/${p.policyId}`} className="font-medium text-ink hover:text-accent">
                  {p.policyName}
                </Link>
              </td>
              <td>{label("policyType", p.policyType)}</td>
              <td>{label("policyEffect", p.effect)}</td>
              <td>
                {p.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
