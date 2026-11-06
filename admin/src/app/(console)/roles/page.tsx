import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, Table } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { query } from "@/lib/queries";
import { ROLE_TYPES, type Role } from "@/lib/types";
import { createRole } from "./actions";
import { SYSTEM_ROLE_CODES } from "./system";

export default function RolesPage() {
  return (
    <>
      <PageHeader title="역할" description="권한 묶음. 사용자·조직·그룹에 부여합니다." />
      <div className="space-y-6">
        <AddPanel label="역할 추가">
          <ActionForm action={createRole} submitLabel="만들기" resetOnSuccess>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="역할 코드">
                <Input name="roleCode" required maxLength={100} />
              </Field>
              <Field label="이름">
                <Input name="roleName" required maxLength={200} />
              </Field>
              <Field label="유형">
                <Select name="roleType">
                  <Options values={ROLE_TYPES} labels={LABELS.roleType} />
                </Select>
              </Field>
              <Field label="우선순위">
                <Input name="priority" type="number" defaultValue={0} />
              </Field>
              <Checkbox name="isSensitive" label="민감 역할" />
              <Checkbox name="isPrivileged" label="특권 역할" />
            </div>
          </ActionForm>
        </AddPanel>
        <Suspense fallback={<Loading />}>
          <RoleList />
        </Suspense>
      </div>
    </>
  );
}

async function RoleList() {
  const roles = await query<Role[]>("/api/v1/roles", "/roles");
  return (
    <Card>
      <Table headers={["코드", "이름", "유형", "구분", "우선순위", "상태"]} empty={roles.length === 0}>
        {roles.map((r) => (
          <tr key={r.roleId} className={r.isActive ? undefined : "text-ink-3"}>
            <td>
              <Mono>{r.roleCode}</Mono>
              {SYSTEM_ROLE_CODES.includes(r.roleCode) && <span className="ml-2 text-xs text-ink-3">시스템 관리</span>}
            </td>
            <td>
              <Link href={`/roles/${r.roleId}`} className="font-medium text-ink hover:text-accent">
                {r.roleName}
              </Link>
            </td>
            <td>{label("roleType", r.roleType)}</td>
            <td className="space-x-1">
              {r.isSensitive && <Badge tone="amber">민감</Badge>}
              {r.isPrivileged && <Badge tone="red">특권</Badge>}
            </td>
            <td className="font-mono tabular-nums">{r.priority}</td>
            <td>
              {r.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
