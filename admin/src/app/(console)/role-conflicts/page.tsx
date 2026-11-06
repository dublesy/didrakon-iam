import Link from "next/link";
import { connection } from "next/server";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Options, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import { RISK_LEVELS, type Role, type RoleConflict } from "@/lib/types";
import { changeConflictActive, defineConflict, endConflictException, grantConflictException, updateConflict } from "./actions";

/** 만료가 없거나 아직 오지 않은 예외 */
function isOpen(validUntil: string | null): boolean {
  return validUntil === null || new Date(validUntil).getTime() > Date.now();
}

const SEVERITY_TONES: Record<string, "zinc" | "amber" | "red"> = { LOW: "zinc", MEDIUM: "amber", HIGH: "red", CRITICAL: "red" };

export default function RoleConflictsPage({ searchParams }: PageProps<"/role-conflicts">) {
  return (
    <>
      <PageHeader
        title="직무 분리"
        description="함께 가질 수 없는 역할 쌍을 정합니다. 규칙을 만들어도 이미 두 역할을 함께 가진 사람의 권한은 회수되지 않습니다."
      />
      <Suspense fallback={<Loading />}>
        <ConflictList searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function ConflictList({ searchParams }: { searchParams: PageProps<"/role-conflicts">["searchParams"] }) {
  const here = "/role-conflicts";
  const { edit } = await searchParams;
  const [conflicts, roles] = await Promise.all([query<RoleConflict[]>("/api/v1/role-conflicts", here), query<Role[]>("/api/v1/roles", here)]);
  const names = await subjectNames(conflicts.flatMap((c) => c.exceptions.map((e) => e.subjectId)), here);
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  // 예외가 끝났는지는 현재 시각 기준이라 요청 시점에 계산한다
  await connection();

  return (
    <div className="space-y-6">
      <AddPanel label="충돌 규칙 추가">
        <ActionForm action={defineConflict} submitLabel="만들기" resetOnSuccess>
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Field label="역할 1">
              <RoleSelect name="roleId1" roles={roles} />
            </Field>
            <Field label="역할 2">
              <RoleSelect name="roleId2" roles={roles} />
            </Field>
            <Field label="심각도">
              <Select name="severity">
                <Options values={RISK_LEVELS} labels={LABELS.risk} />
              </Select>
            </Field>
            <Field label="설명 (선택)">
              <Input name="description" maxLength={1000} />
            </Field>
          </div>
        </ActionForm>
      </AddPanel>
      {conflicts.length === 0 && (
        <Card>
          <p className="text-ink-3">직무 분리 규칙이 없습니다</p>
        </Card>
      )}
      {conflicts.map((c) => (
        <Card key={c.conflictId}>
          <div className="mb-2 flex flex-wrap items-center gap-2">
            <span className="font-semibold text-ink">
              {roleName.get(c.roleIdA) ?? c.roleIdA} ↔ {roleName.get(c.roleIdB) ?? c.roleIdB}
            </span>
            <Badge tone={SEVERITY_TONES[c.severity] ?? "zinc"}>{label("risk", c.severity)}</Badge>
            {!c.isActive && <Badge>꺼짐</Badge>}
            <span className="ml-auto flex items-center gap-2">
              {String(c.conflictId) === edit ? (
                <Link href={here} className={buttonClass.row}>
                  닫기
                </Link>
              ) : (
                <Link href={`${here}?edit=${c.conflictId}`} className={buttonClass.row}>
                  수정
                </Link>
              )}
              <RowAction
                action={changeConflictActive}
                label={c.isActive ? "끄기" : "켜기"}
                tone={c.isActive ? "danger" : "neutral"}
                hidden={{ conflictId: c.conflictId, active: String(!c.isActive) }}
                confirmMessage={c.isActive ? "끄면 두 역할을 함께 부여할 수 있게 됩니다. 끌까요?" : undefined}
              />
            </span>
          </div>
          {String(c.conflictId) === edit && (
            <ActionForm key={c.conflictId} action={updateConflict} submitLabel="저장" className="mb-5 border-b border-line pb-5">
              <input type="hidden" name="conflictId" value={c.conflictId} />
              <p className="mb-4 text-ink-3">역할 쌍은 바꿀 수 없습니다. 다른 쌍이 필요하면 새 규칙을 만들고 이 규칙을 끄세요</p>
              <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
                <Field label="심각도">
                  <Select name="severity" defaultValue={c.severity}>
                    <Options values={RISK_LEVELS} labels={LABELS.risk} />
                  </Select>
                </Field>
                <Field label="설명 (선택)">
                  <Input name="description" maxLength={1000} defaultValue={c.description ?? ""} />
                </Field>
              </div>
            </ActionForm>
          )}
          {c.description && <p className="mb-3 text-ink-2">{c.description}</p>}
          <h3 className="mb-2 text-[13px] font-medium text-ink-2">예외</h3>
          <Table headers={["대상자", "사유", "만료", ""]} empty={c.exceptions.length === 0}>
            {c.exceptions.map((e) => {
              const open = isOpen(e.validUntil);
              return (
                <tr key={e.exceptionId} className={open ? undefined : "text-ink-3"}>
                  <td>{names.get(e.subjectId) ?? e.subjectId}</td>
                  <td>{e.reason}</td>
                  <td>{formatTime(e.validUntil)}</td>
                  <td className="text-right">
                    {open ? (
                      <RowAction
                        action={endConflictException}
                        label="끝내기"
                        hidden={{ exceptionId: e.exceptionId }}
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
          <ActionForm action={grantConflictException} submitLabel="예외 허용" variant="subtle" resetOnSuccess className="mt-4">
            <input type="hidden" name="conflictId" value={c.conflictId} />
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="대상 subject ID">
                <Input name="subjectId" type="number" min={1} required />
              </Field>
              <Field label="사유">
                <Input name="reason" required maxLength={1000} />
              </Field>
              <Field label="만료 (선택)">
                <Input name="validUntil" type="datetime-local" />
              </Field>
            </div>
          </ActionForm>
        </Card>
      ))}

    </div>
  );
}

function RoleSelect({ name, roles }: { name: string; roles: Role[] }) {
  return (
    <Select name={name} required>
      {roles.map((r) => (
        <option key={r.roleId} value={r.roleId}>
          {r.roleName} ({r.roleCode})
        </option>
      ))}
    </Select>
  );
}
