import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { Badge, Card, Field, Input, Loading, Mono, PageHeader, Select, Table, Textarea, buttonClass } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import type { Group, GroupMember, GroupRole, Role, Scope } from "@/lib/types";
import { addGroupMember, changeGroupActive, createGroupRole, deleteGroupRole, removeGroupMember, updateGroup } from "../actions";


export default function GroupDetailPage({ params, searchParams }: PageProps<"/groups/[id]">) {
  return (
    <Suspense fallback={<Loading />}>
      <GroupDetail params={params} searchParams={searchParams} />
    </Suspense>
  );
}

async function GroupDetail({ params, searchParams }: { params: PageProps<"/groups/[id]">["params"]; searchParams: PageProps<"/groups/[id]">["searchParams"] }) {
  const { id } = await params;
  const editing = (await searchParams).edit === "1";
  const here = `/groups/${id}`;
  // 단건 조회 API 가 없어 목록에서 찾는다
  const [groups, members, rules, roles, scopes] = await Promise.all([
    query<Group[]>("/api/v1/groups", here),
    query<GroupMember[]>(`/api/v1/groups/${id}/members`, here),
    query<GroupRole[]>(`/api/v1/groups/${id}/roles`, here),
    query<Role[]>("/api/v1/roles", here),
    query<Scope[]>("/api/v1/scopes", here),
  ]);
  const group = groups.find((g) => String(g.groupId) === id);
  if (!group) notFound();
  const names = await subjectNames(members.map((m) => m.subjectId), here);
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  const scopeCode = new Map(scopes.map((s) => [s.scopeId, s.scopeCode]));

  return (
    <>
      <PageHeader title={group.groupName} description={`코드 ${group.groupCode} · ${label("groupType", group.groupType)}`}>
        <Link href="/groups" className={buttonClass.secondary}>
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
              {group.isActive ? (
                <RowAction
                  action={changeGroupActive}
                  label="끄기"
                  hidden={{ groupId: id, active: "false" }}
                  confirmMessage={`'${group.groupName}' 그룹을 끌까요? 구성원이 남아 있으면 끌 수 없습니다`}
                />
              ) : (
                <RowAction action={changeGroupActive} label="켜기" tone="neutral" hidden={{ groupId: id, active: "true" }} />
              )}
            </span>
          }
        >
          {editing ? (
            <ActionForm key={group.groupId} action={updateGroup} submitLabel="저장">
              <input type="hidden" name="groupId" value={id} />
              <p className="mb-4 text-ink-3">코드({group.groupCode})와 유형은 바꿀 수 없습니다</p>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
                <Field label="이름">
                  <Input name="groupName" required maxLength={200} defaultValue={group.groupName} />
                </Field>
              </div>
              {group.groupType === "DYNAMIC" && (
                <div className="mt-3">
                  <Field label="규칙식">
                    <Textarea name="ruleExpression" rows={2} defaultValue={group.ruleExpression ?? ""} />
                  </Field>
                </div>
              )}
            </ActionForm>
          ) : (
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
              <dt className="text-ink-3">상태</dt>
              <dd>{group.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}</dd>
              <dt className="text-ink-3">유형</dt>
              <dd>{label("groupType", group.groupType)}</dd>
              {group.groupType === "DYNAMIC" && (
                <>
                  <dt className="text-ink-3">규칙식</dt>
                  <dd>
                    <Mono>{group.ruleExpression ?? "—"}</Mono>
                  </dd>
                </>
              )}
            </dl>
          )}
        </Card>

        <Card title="구성원">
          <Table headers={["이름", "출처", "시작", ""]} empty={members.length === 0}>
            {members.map((m) => (
              <tr key={m.subjectId}>
                <td>
                  <Link href={`/users/${m.subjectId}`} className="font-medium text-ink hover:text-accent">
                    {names.get(m.subjectId) ?? m.subjectId}
                  </Link>
                </td>
                <td>{label("groupSource", m.sourceType)}</td>
                <td>{formatTime(m.validFrom)}</td>
                <td>
                  <RowAction
                    action={removeGroupMember}
                    label="빼기"
                    hidden={{ groupId: id, subjectId: m.subjectId }}
                    confirmMessage="이 구성원을 그룹에서 뺄까요? 그룹 역할도 함께 회수됩니다."
                  />
                </td>
              </tr>
            ))}
          </Table>
          <ActionForm action={addGroupMember} submitLabel="구성원 추가" resetOnSuccess className="mt-4 flex items-end gap-3">
            <input type="hidden" name="groupId" value={id} />
            <Field label="Subject ID">
              <Input name="subjectId" type="number" min={1} required className="font-mono" />
            </Field>
          </ActionForm>
        </Card>

        <Card title="그룹 역할 규칙">
          <p className="mb-4 text-ink-3">이 그룹 구성원에게 자동으로 주는 역할</p>
          <Table headers={["역할", "범위", ""]} empty={rules.length === 0}>
            {rules.map((r) => (
              <tr key={r.groupRoleId}>
                <td>{roleName.get(r.roleId) ?? r.roleId}</td>
                <td>
                  <Mono>{scopeCode.get(r.scopeId) ?? r.scopeId}</Mono>
                </td>
                <td>
                  <RowAction
                    action={deleteGroupRole}
                    label="삭제"
                    hidden={{ groupId: id, groupRoleId: r.groupRoleId }}
                    confirmMessage="이 규칙을 삭제할까요? 규칙으로 받은 역할이 회수됩니다."
                  />
                </td>
              </tr>
            ))}
          </Table>
          <ActionForm action={createGroupRole} submitLabel="규칙 추가" resetOnSuccess className="mt-4">
            <input type="hidden" name="groupId" value={id} />
            <div className="grid grid-cols-2 gap-3">
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
            </div>
          </ActionForm>
        </Card>
      </div>
    </>
  );
}
