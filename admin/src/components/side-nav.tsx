"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { RESOURCE } from "@/lib/admin-scope";

/** resource 가 있는 메뉴는 그 관리 리소스를 조회할 수 있을 때만 보인다. 내 계정·연동 가이드는 항상 보인다 */
const MENU: { group: string; items: { href: string; label: string; resource?: string }[] }[] = [
  {
    group: "내 계정",
    items: [
      { href: "/", label: "내 정보" },
      { href: "/mfa", label: "2단계 인증" },
      { href: "/my-reviews", label: "내 검토 할 일" },
      { href: "/my-access", label: "내 권한 요청" },
    ],
  },
  {
    group: "사람과 조직",
    items: [
      { href: "/users", label: "사용자", resource: RESOURCE.USER },
      { href: "/organizations", label: "조직", resource: RESOURCE.ORGANIZATION },
      { href: "/groups", label: "그룹", resource: RESOURCE.GROUP },
    ],
  },
  {
    group: "권한",
    items: [
      { href: "/roles", label: "역할", resource: RESOURCE.ROLE },
      { href: "/resources", label: "리소스·권한", resource: RESOURCE.RESOURCE },
      { href: "/scopes", label: "범위", resource: RESOURCE.SCOPE },
      { href: "/policies", label: "정책", resource: RESOURCE.POLICY },
      { href: "/role-conflicts", label: "직무 분리", resource: RESOURCE.SOD },
    ],
  },
  {
    group: "운영",
    items: [
      { href: "/approvals", label: "승인 대기", resource: RESOURCE.ACCESS_REQUEST },
      { href: "/break-glass", label: "비상 접근", resource: RESOURCE.BREAK_GLASS },
      { href: "/delegations", label: "위임", resource: RESOURCE.DELEGATION },
      { href: "/access-reviews", label: "접근 재검토", resource: RESOURCE.REVIEW },
      { href: "/risk-policies", label: "위험 정책", resource: RESOURCE.RISK },
      { href: "/hr-sync", label: "HR 연동", resource: RESOURCE.HR_SYNC },
      { href: "/webhooks", label: "웹훅", resource: RESOURCE.WEBHOOK },
      { href: "/audit", label: "감사 기록", resource: RESOURCE.AUDIT },
    ],
  },
  {
    group: "개발자",
    items: [{ href: "/developers", label: "연동 가이드" }],
  },
];

/**
 * 왼쪽 메뉴. 현재 위치를 강조색 바탕으로 표시한다.
 * [readable] 은 조회할 수 있는 관리 리소스 키. null 이면(관리 범위를 읽지 못함) 모든 메뉴를 보여주고 각 화면이 권한을 판정한다
 */
export function SideNav({ readable }: { readable: string[] | null }) {
  return <Menu pathname={usePathname()} readable={readable} />;
}

/** 경로·관리 범위를 읽기 전 자리. 내 계정 메뉴만 강조 없이 보여준다 */
export function SideNavFallback() {
  return <Menu pathname={null} readable={[]} />;
}

function Menu({ pathname, readable }: { pathname: string | null; readable: string[] | null }) {
  const isActive = (href: string) =>
    pathname !== null && (href === "/" ? pathname === "/" : pathname === href || pathname.startsWith(`${href}/`));
  const sections = MENU.map((section) => ({
    ...section,
    items: section.items.filter((item) => item.resource === undefined || readable === null || readable.includes(item.resource)),
  })).filter((section) => section.items.length > 0);

  return (
    <nav aria-label="주 메뉴" className="flex flex-col gap-6 px-3 py-4">
      {sections.map((section) => (
        <div key={section.group} className="flex flex-col gap-0.5">
          <span className="mb-1 px-2 text-xs font-medium text-ink-3">{section.group}</span>
          {section.items.map((item) => {
            const active = isActive(item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? "page" : undefined}
                className={`flex h-8 items-center rounded-md px-2 transition-colors ${
                  active ? "bg-accent-soft font-medium text-accent" : "text-ink-2 hover:bg-surface hover:text-ink"
                }`}
              >
                {item.label}
              </Link>
            );
          })}
        </div>
      ))}
    </nav>
  );
}
