import Link from "next/link";
import { Suspense } from "react";
import { Card, Loading, Mono, PageHeader } from "@/components/ui";
import { label } from "@/lib/labels";
import { RESOURCE, can } from "@/lib/admin-scope";
import { adminScope, query } from "@/lib/queries";
import type { Group, Organization, Page, Role, User } from "@/lib/types";

/** 상단 전역 검색 결과. 사용자는 서버 검색, 조직·그룹·역할은 목록에서 걸러 낸다. 조회 권한이 없는 영역은 부르지 않는다 */
export default function SearchPage({ searchParams }: PageProps<"/search">) {
  return (
    <>
      <PageHeader title="검색" />
      <Suspense fallback={<Loading />}>
        <Results searchParams={searchParams} />
      </Suspense>
    </>
  );
}

type Hit = { href: string; name: string; code: string; meta: string };

async function Results({ searchParams }: { searchParams: PageProps<"/search">["searchParams"] }) {
  const params = await searchParams;
  const q = (typeof params.q === "string" ? params.q : "").trim();
  if (!q) return <p className="text-ink-3">검색어를 입력하세요</p>;

  const returnTo = `/search?q=${encodeURIComponent(q)}`;
  const scope = await adminScope(returnTo);
  const empty: Page<User> = { items: [], page: 0, size: 10, total: 0 };
  const [users, orgs, groups, roles] = await Promise.all([
    can(scope, RESOURCE.USER) ? query<Page<User>>(`/api/v1/users?q=${encodeURIComponent(q)}&page=0&size=10`, returnTo) : empty,
    can(scope, RESOURCE.ORGANIZATION) ? query<Organization[]>("/api/v1/organizations", returnTo) : [],
    can(scope, RESOURCE.GROUP) ? query<Group[]>("/api/v1/groups", returnTo) : [],
    can(scope, RESOURCE.ROLE) ? query<Role[]>("/api/v1/roles", returnTo) : [],
  ]);
  const needle = q.toLowerCase();
  const matches = (...values: string[]) => values.some((v) => v.toLowerCase().includes(needle));

  const sections: { title: string; hits: Hit[]; more?: string }[] = [
    {
      title: "사용자",
      hits: users.items.map((u) => ({
        href: `/users/${u.subjectId}`,
        name: u.name,
        code: u.empNo ?? u.email ?? "",
        meta: `${label("userKind", u.userKind)} · ${label("subjectStatus", u.status)}`,
      })),
      more: users.total > users.items.length ? `/users?q=${encodeURIComponent(q)}` : undefined,
    },
    {
      title: "조직",
      hits: orgs
        .filter((o) => matches(o.orgName, o.orgCode))
        .map((o) => ({ href: `/organizations/${o.orgId}`, name: o.orgName, code: o.orgCode, meta: label("orgType", o.orgType) })),
    },
    {
      title: "그룹",
      hits: groups
        .filter((g) => matches(g.groupName, g.groupCode))
        .map((g) => ({ href: `/groups/${g.groupId}`, name: g.groupName, code: g.groupCode, meta: label("groupType", g.groupType) })),
    },
    {
      title: "역할",
      hits: roles
        .filter((r) => matches(r.roleName, r.roleCode))
        .map((r) => ({ href: `/roles/${r.roleId}`, name: r.roleName, code: r.roleCode, meta: label("roleType", r.roleType) })),
    },
  ];
  const found = sections.filter((s) => s.hits.length > 0);

  if (found.length === 0) return <p className="text-ink-3">‘{q}’와 일치하는 항목이 없습니다</p>;

  return (
    <div className="space-y-4">
      <p className="text-ink-3">‘{q}’ 검색 결과</p>
      {found.map((s) => (
        <Card key={s.title} title={`${s.title} ${s.hits.length}`} actions={s.more && <Link href={s.more} className="text-accent hover:underline">전체 보기</Link>}>
          <ul className="-mx-5 divide-y divide-line border-t border-line">
            {s.hits.slice(0, 10).map((h) => (
              <li key={h.href}>
                <Link href={h.href} className="flex h-10 items-center gap-3 px-5 hover:bg-canvas">
                  <span className="font-medium text-ink">{h.name}</span>
                  <Mono>{h.code}</Mono>
                  <span className="ml-auto text-ink-3">{h.meta}</span>
                </Link>
              </li>
            ))}
          </ul>
        </Card>
      ))}
    </div>
  );
}
