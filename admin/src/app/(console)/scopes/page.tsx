import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { query } from "@/lib/queries";
import { SCOPE_TYPES, type Organization, type Resource, type Scope } from "@/lib/types";
import { OrgOptions } from "../organizations/org-options";
import { changeScopeActive, createScope, updateScope } from "./actions";

export default function ScopesPage({ searchParams }: PageProps<"/scopes">) {
  return (
    <>
      <PageHeader title="범위 (scope)" description="역할·권한이 적용되는 범위. 전체 범위는 하나만 있습니다." />
      <Suspense fallback={<Loading />}>
        <ScopeList searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function ScopeList({ searchParams }: { searchParams: PageProps<"/scopes">["searchParams"] }) {
  const params = await searchParams;
  const [scopes, orgs, resources] = await Promise.all([
    query<Scope[]>("/api/v1/scopes", "/scopes"),
    query<Organization[]>("/api/v1/organizations", "/scopes"),
    query<Resource[]>("/api/v1/resources", "/scopes"),
  ]);
  const orgName = new Map(orgs.map((o) => [o.orgId, o.orgName]));
  const resourceName = new Map(resources.map((r) => [r.resourceId, r.resourceName]));
  const target = (s: Scope) => {
    if (s.orgId !== null) return `조직: ${orgName.get(s.orgId) ?? s.orgId}`;
    if (s.resourceId !== null) return `리소스: ${resourceName.get(s.resourceId) ?? s.resourceId}`;
    return "—";
  };
  const editing = scopes.find((s) => String(s.scopeId) === params.edit);

  return (
    <div className="space-y-6">
      {editing ? (
        <Card title={`${editing.scopeName} 수정`} actions={<Link href="/scopes" className="text-ink-2 hover:text-ink">닫기</Link>}>
          <p className="mb-4 text-ink-3">코드·유형·대상은 바꿀 수 없습니다</p>
          <ActionForm key={editing.scopeId} action={updateScope} submitLabel="저장">
            <input type="hidden" name="scopeId" value={editing.scopeId} />
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="이름">
                <Input name="scopeName" required maxLength={200} defaultValue={editing.scopeName} />
              </Field>
              <div className="flex items-end">
                <Checkbox name="includeDescendants" label="하위 포함" defaultChecked={editing.includeDescendants} />
              </div>
            </div>
          </ActionForm>
        </Card>
      ) : (
        <AddPanel label="범위 추가">
          <ActionForm action={createScope} submitLabel="만들기" resetOnSuccess>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="코드">
                <Input name="scopeCode" required maxLength={100} />
              </Field>
              <Field label="이름">
                <Input name="scopeName" required maxLength={200} />
              </Field>
              <Field label="유형">
                <Select name="scopeType">
                  <Options values={SCOPE_TYPES} labels={LABELS.scopeType} />
                </Select>
              </Field>
              <Field label="조직" hint="유형이 조직이면 필수">
                <Select name="orgId">
                  <option value="">선택 안 함</option>
                  <OrgOptions orgs={orgs} />
                </Select>
              </Field>
              <Field label="리소스" hint="유형이 리소스면 필수">
                <Select name="resourceId">
                  <option value="">선택 안 함</option>
                  {resources.map((r) => (
                    <option key={r.resourceId} value={r.resourceId}>
                      {r.resourceName} ({r.resourceKey})
                    </option>
                  ))}
                </Select>
              </Field>
              <div className="flex items-end">
                <Checkbox name="includeDescendants" label="하위 포함" />
              </div>
            </div>
          </ActionForm>
        </AddPanel>
      )}
      <Card>
        <Table headers={["코드", "이름", "유형", "대상", "하위 포함", "상태", ""]} empty={scopes.length === 0}>
          {scopes.map((s) => (
            <tr key={s.scopeId} className={s.isActive ? undefined : "text-ink-3"}>
              <td>
                <Mono>{s.scopeCode}</Mono>
              </td>
              <td>{s.scopeName}</td>
              <td>{label("scopeType", s.scopeType)}</td>
              <td>{target(s)}</td>
              <td>{s.includeDescendants ? "예" : ""}</td>
              <td>{s.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}</td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link
                    href={`/scopes?edit=${s.scopeId}`}
                    className={buttonClass.row}
                  >
                    수정
                  </Link>
                  {s.scopeType !== "GLOBAL" && (
                    <RowAction
                      action={changeScopeActive}
                      label={s.isActive ? "끄기" : "켜기"}
                      tone={s.isActive ? "danger" : "neutral"}
                      hidden={{ scopeId: s.scopeId, active: String(!s.isActive) }}
                      confirmMessage={s.isActive ? `'${s.scopeName}' 범위를 끌까요? 이 범위로 준 권한이 판정에서 빠집니다` : undefined}
                    />
                  )}
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
