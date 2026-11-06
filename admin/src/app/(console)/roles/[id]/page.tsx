import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { query } from "@/lib/queries";
import { ROLE_TYPES, type Permission, type Resource, type RoleDetail, type Scope } from "@/lib/types";
import { changeRoleActive, grantPermission, removeRolePermission, updateRole } from "../actions";
import { SYSTEM_ROLE_CODES } from "../system";


export default function RoleDetailPage({ params, searchParams }: PageProps<"/roles/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      <RoleDetailView params={params} searchParams={searchParams} />
    </Suspense>
  );
}

async function RoleDetailView({ params, searchParams }: Pick<PageProps<"/roles/[id]">, "params" | "searchParams">) {
  const { id } = await params;
  const editing = (await searchParams).edit !== undefined;
  const here = `/roles/${id}`;
  const [detail, permissions, resources, scopes] = await Promise.all([
    query<RoleDetail>(`/api/v1/roles/${id}`, here),
    query<Permission[]>("/api/v1/permissions", here),
    query<Resource[]>("/api/v1/resources", here),
    query<Scope[]>("/api/v1/scopes", here),
  ]);
  const { role } = detail;
  const resourceKey = new Map(resources.map((r) => [r.resourceId, r.resourceKey]));

  return (
    <>
      <PageHeader title={role.roleName} description={`역할 코드 ${role.roleCode}`}>
        <Link href="/roles" className="font-medium text-ink hover:text-accent">
          목록
        </Link>
      </PageHeader>

      <div className="space-y-6">
        <Card
          title="기본 정보"
          actions={
            <span className="flex gap-2">
              <Link href={editing ? here : `${here}?edit=1`} className={buttonClass.row}>
                {editing ? "닫기" : "수정"}
              </Link>
              <RowAction
                action={changeRoleActive}
                label={role.isActive ? "끄기" : "켜기"}
                tone={role.isActive ? "danger" : "neutral"}
                hidden={{ roleId: id, active: String(!role.isActive) }}
                confirmMessage={role.isActive ? "이 역할을 가진 사람의 권한이 판정에서 빠집니다. 끌까요?" : undefined}
              />
            </span>
          }
        >
          {SYSTEM_ROLE_CODES.includes(role.roleCode) && <p className="mb-3 text-xs text-ink-3">IAM 시스템 역할. 기동 시 코드가 관리합니다</p>}
          <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
            <dt className="text-ink-3">유형</dt>
            <dd>{label("roleType", role.roleType)}</dd>
            <dt className="text-ink-3">구분</dt>
            <dd className="space-x-1">
              {role.isSensitive && <Badge tone="amber">민감</Badge>}
              {role.isPrivileged && <Badge tone="red">특권</Badge>}
              {!role.isSensitive && !role.isPrivileged && "—"}
            </dd>
            <dt className="text-ink-3">우선순위</dt>
            <dd className="font-mono tabular-nums">{role.priority}</dd>
            <dt className="text-ink-3">상태</dt>
            <dd>
              {role.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}
            </dd>
          </dl>
          {editing && (
            <ActionForm action={updateRole} submitLabel="저장" className="mt-5 border-t border-line pt-5">
              <input type="hidden" name="roleId" value={id} />
              <p className="mb-4 text-ink-3">역할 코드는 바꿀 수 없습니다</p>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Field label="이름">
                  <Input name="roleName" required maxLength={200} defaultValue={role.roleName} />
                </Field>
                <Field label="유형">
                  <Select name="roleType" defaultValue={role.roleType}>
                    <Options values={ROLE_TYPES} labels={LABELS.roleType} />
                  </Select>
                </Field>
                <Field label="우선순위">
                  <Input name="priority" type="number" defaultValue={role.priority} />
                </Field>
                <div />
                <Checkbox name="isSensitive" label="민감 역할" defaultChecked={role.isSensitive} />
                <Checkbox name="isPrivileged" label="특권 역할" defaultChecked={role.isPrivileged} />
              </div>
            </ActionForm>
          )}
        </Card>

        <Card title="포함된 권한">
          <Table headers={["권한 코드", "리소스", "동작", "효과", "범위", ""]} empty={detail.permissions.length === 0}>
            {detail.permissions.map((rp) => (
              <tr key={rp.rolePermissionId}>
                <td>
                  <Mono>{rp.permission.permissionCode}</Mono>
                </td>
                <td>
                  <Mono>{resourceKey.get(rp.permission.resourceId) ?? rp.permission.resourceId}</Mono>
                </td>
                <td>{label("action", rp.permission.action)}</td>
                <td>
                  <Badge tone={rp.permission.effect === "DENY" ? "red" : "green"}>{label("effect", rp.permission.effect)}</Badge>
                </td>
                <td>
                  <Mono>{rp.scope.scopeCode}</Mono>
                </td>
                <td className="text-right">
                  <RowAction
                    action={removeRolePermission}
                    label="빼기"
                    hidden={{ roleId: id, rolePermissionId: rp.rolePermissionId }}
                    confirmMessage={`'${rp.permission.permissionCode}' 권한을 이 역할에서 뺄까요?`}
                  />
                </td>
              </tr>
            ))}
          </Table>
          <ActionForm action={grantPermission} submitLabel="권한 추가" resetOnSuccess className="mt-4">
            <input type="hidden" name="roleId" value={id} />
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <Field label="권한">
                <Select name="permissionId" required>
                  {permissions.map((p) => (
                    <option key={p.permissionId} value={p.permissionId}>
                      {resourceKey.get(p.resourceId) ?? p.resourceId} · {p.permissionCode} ({label("action", p.action)} {label("effect", p.effect)})
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
            </div>
          </ActionForm>
        </Card>
      </div>
    </>
  );
}
