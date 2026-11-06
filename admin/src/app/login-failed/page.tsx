import { BrandMark } from "@/components/brand-mark";
import { buttonClass } from "@/components/ui";

/** 로그인 전 화면이라 관리 메뉴 없이 가운데에 둔다 (IAM 로그인 화면과 같은 모양) */
export default function LoginFailed() {
  return (
    <main className="flex min-h-screen flex-col items-center justify-center px-4">
      <BrandMark className="size-[52px] text-accent [--mark-eye:var(--canvas)]" />
      <p className="mt-3 mb-6 text-[15px] font-semibold tracking-wide text-ink">DIDRAKON IAM</p>
      <section className="w-full max-w-sm rounded-xl border border-line bg-surface p-7">
        <h1 className="text-xl font-semibold text-ink">로그인하지 못했습니다</h1>
        <p className="mt-1 mb-5 text-ink-3">로그인 요청이 만료되었거나 올바르지 않습니다. 다시 시도하세요</p>
        <a href="/auth/login" className={`${buttonClass.primary} w-full`}>
          다시 로그인
        </a>
      </section>
    </main>
  );
}
