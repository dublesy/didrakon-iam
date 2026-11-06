import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, Options, PageHeader, Select, Table } from "@/components/ui";
import { RESOURCE, can } from "@/lib/admin-scope";
import { LABELS, label } from "@/lib/labels";
import { adminScope, query } from "@/lib/queries";
import { USER_KINDS, type Organization, type Page, type User } from "@/lib/types";
import { OrgOptions } from "../organizations/org-options";
import { createUser } from "./actions";

const PAGE_SIZE = 20;

export default function UsersPage({ searchParams }: PageProps<"/users">) {
  return (
    <>
      <PageHeader title="사용자" description="내부 임직원과 외부 사용자(고객사 등) 계정. 로그인 ID를 넣으면 로그인 계정도 함께 만듭니다." />
      <div className="space-y-6">
        <Suspense fallback={null}>
          <CreateUser />
        </Suspense>
        <Suspense fallback={<Loading />}>
          <UserList searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

/** 만들 권한이 있을 때만 보인다. 조직 단위 관리자는 자기 범위 안 조직을 골라야 한다 */
async function CreateUser() {
  const scope = await adminScope("/users");
  if (!can(scope, RESOURCE.USER, "CREATE")) return null;
  const orgs = can(scope, RESOURCE.ORGANIZATION) ? await query<Organization[]>("/api/v1/organizations", "/users") : [];

  return (
    <AddPanel label="사용자 추가">
      <ActionForm action={createUser} submitLabel="만들기" resetOnSuccess>
        <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
          <Field label="구분" hint="외부 사용자는 사번 없이 이메일로 식별합니다">
            <Select name="userKind" defaultValue="EMPLOYEE">
              <Options values={USER_KINDS} labels={LABELS.userKind} />
            </Select>
          </Field>
          <Field label="소속 조직" hint={scope.global ? "외부 사용자는 고객사 조직이 필요합니다" : "관리 범위 안 조직만 고를 수 있습니다"}>
            <Select name="primaryOrgId" required={!scope.global}>
              {scope.global && <option value="">없음</option>}
              <OrgOptions orgs={orgs.filter((o) => o.isActive)} />
            </Select>
          </Field>
          <span />
          <Field label="사번" hint="내부 임직원은 필수">
            <Input name="empNo" maxLength={50} />
          </Field>
          <Field label="이름">
            <Input name="name" required maxLength={200} />
          </Field>
          <Field label="이메일" hint="외부 사용자는 필수">
            <Input name="email" type="email" maxLength={255} />
          </Field>
          <Field label="전화">
            <Input name="phone" maxLength={30} />
          </Field>
          <Field label="입사일">
            <Input name="hireDate" type="date" />
          </Field>
          <span />
          <Field label="로그인 ID" hint="비우면 로그인 계정 없이 만듭니다">
            <Input name="loginId" maxLength={100} autoComplete="off" />
          </Field>
          <Field label="초기 비밀번호" hint="10자 이상, 로그인 ID 포함 불가">
            <Input name="password" type="password" autoComplete="new-password" />
          </Field>
        </div>
      </ActionForm>
    </AddPanel>
  );
}

async function UserList({ searchParams }: { searchParams: PageProps<"/users">["searchParams"] }) {
  const params = await searchParams;
  const q = typeof params.q === "string" ? params.q : "";
  const kind = typeof params.kind === "string" && (USER_KINDS as readonly string[]).includes(params.kind) ? params.kind : "";
  const page = Math.max(0, Number(params.page ?? 0) || 0);
  const filter = `q=${encodeURIComponent(q)}${kind ? `&kind=${kind}` : ""}`;
  const result = await query<Page<User>>(`/api/v1/users?${filter}&page=${page}&size=${PAGE_SIZE}`, "/users");
  const lastPage = Math.max(0, Math.ceil(result.total / PAGE_SIZE) - 1);
  const link = (p: number) => `/users?${filter}&page=${p}`;

  return (
    <Card>
      <form className="mb-4 flex gap-2" role="search">
        <Input name="q" defaultValue={q} placeholder="이름, 사번 또는 이메일" aria-label="검색어" className="w-64" />
        <Select name="kind" defaultValue={kind} aria-label="구분" className="w-32">
          <option value="">전체</option>
          <Options values={USER_KINDS} labels={LABELS.userKind} />
        </Select>
        <button type="submit" className="h-9 rounded-lg border border-line-strong bg-surface px-3 font-medium text-ink transition-colors hover:bg-panel">
          검색
        </button>
      </form>
      <Table headers={["구분", "사번", "이름", "이메일", "상태", "재직"]} empty={result.items.length === 0}>
        {result.items.map((u) => (
          <tr key={u.subjectId}>
            <td>
              <Badge tone={u.userKind === "EXTERNAL" ? "blue" : "zinc"}>{label("userKind", u.userKind)}</Badge>
            </td>
            <td>{u.empNo ? <Mono>{u.empNo}</Mono> : "—"}</td>
            <td>
              <Link href={`/users/${u.subjectId}`} className="font-medium text-ink hover:text-accent">
                {u.name}
              </Link>
            </td>
            <td className="text-ink-2">{u.email ?? "—"}</td>
            <td>
              <Badge tone={u.status === "ACTIVE" ? "green" : "red"}>{label("subjectStatus", u.status)}</Badge>
            </td>
            <td>{label("employment", u.employmentStatus)}</td>
          </tr>
        ))}
      </Table>
      <nav className="mt-4 flex items-center gap-3 text-[13px]" aria-label="페이지">
        <span className="text-ink-3">
          {result.total}명 · {page + 1}/{lastPage + 1}쪽
        </span>
        {page > 0 && <Link href={link(page - 1)} className="font-medium text-ink hover:text-accent">
            이전
          </Link>}
        {page < lastPage && <Link href={link(page + 1)} className="font-medium text-ink hover:text-accent">
            다음
          </Link>}
      </nav>
    </Card>
  );
}
