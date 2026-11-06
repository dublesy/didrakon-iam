import Link from "next/link";
import { Suspense } from "react";
import { BrandMark } from "@/components/brand-mark";
import { SideNav, SideNavFallback } from "@/components/side-nav";
import { readableResources, type AdminScope } from "@/lib/admin-scope";
import { callIam } from "@/lib/iam-api";
import { isExpired, readSession } from "@/lib/session";

/** 관리 화면 뼈대: 왼쪽 메뉴 + 상단 전역 검색. 로그인 실패처럼 로그인 전 화면은 이 그룹 밖에 둔다 */
export default function ConsoleLayout({ children }: LayoutProps<"/">) {
  return (
    <div className="flex min-h-screen">
      <aside className="sticky top-0 flex h-screen w-60 shrink-0 flex-col border-r border-line bg-panel">
        <Link href="/" className="flex h-14 items-center gap-2.5 px-4 text-[15px] font-semibold tracking-tight text-ink">
          <BrandMark className="size-[30px] text-accent [--mark-eye:var(--panel)]" />
          DIDRAKON IAM
        </Link>
        <div className="flex-1 overflow-y-auto">
          <Suspense fallback={<SideNavFallback />}>
            <ScopedSideNav />
          </Suspense>
        </div>
      </aside>
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="sticky top-0 z-10 flex h-14 items-center gap-4 border-b border-line bg-canvas/95 px-8 backdrop-blur-none">
          <form action="/search" role="search" className="w-full max-w-md">
            <label className="sr-only" htmlFor="global-search">
              사용자·조직·그룹·역할 검색
            </label>
            <input
              id="global-search"
              name="q"
              placeholder="이름, 사번, 코드로 검색"
              className="h-9 w-full rounded-lg border border-field-line bg-surface px-3 placeholder:text-ink-3 focus:border-accent focus:outline-none"
            />
          </form>
          <form action="/auth/logout" method="post" className="ml-auto">
            <button type="submit" className="h-9 rounded-lg px-3 text-ink-2 transition-colors hover:bg-panel hover:text-ink">
              로그아웃
            </button>
          </form>
        </header>
        <main className="flex-1 px-8 py-8">
          <div className="mx-auto max-w-6xl">{children}</div>
        </main>
      </div>
    </div>
  );
}

/**
 * 본인 관리 범위에 맞춘 메뉴. 세션이 없거나 만료됐으면 다시 로그인시키는 일은 각 화면에 맡기고(돌아올 경로를 아는 쪽),
 * 여기서는 내 계정 메뉴만 보여준다. 범위를 읽지 못하면 전체 메뉴를 보여준다.
 */
async function ScopedSideNav() {
  const session = await readSession();
  if (!session || isExpired(session)) return <SideNavFallback />;
  const result = await callIam<AdminScope>("/api/v1/me/admin-scope");
  return <SideNav readable={result.ok ? readableResources(result.data) : null} />;
}
