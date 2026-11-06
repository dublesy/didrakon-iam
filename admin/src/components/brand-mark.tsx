/**
 * DIDRAKON 마크. 마주 보는 두 용(인증·인가)이 열쇠 구멍(문)을 지킨다.
 * 색은 currentColor, 눈은 바탕색과 같게 --mark-eye 로 맞춘다. 파비콘(app/icon.svg)·로그인 화면(static/iam-login)과 같은 모양을 유지한다
 */
const BODY =
  "M7.2 28.6C7 24 4.4 20.5 5.2 15.2 5.8 11.6 7.4 9.4 8.6 8.2L6.6 3.6 10.6 6.6 14.8 7.6 15 8.8 12.4 9.2 14.2 10.4 11.4 10.8C9.6 11.6 8.4 13.2 8.1 15.4 7.6 19.6 9.6 23.4 9.4 28.6Q8.3 29.4 7.2 28.6ZM5.3 20.2 2.5 19.3 4.9 17.6ZM5.5 14.6 3 13 5.9 12.2Z";

export function BrandMark({ className = "", title }: { className?: string; title?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} fill="currentColor" role={title ? "img" : undefined} aria-hidden={title ? undefined : true} aria-label={title}>
      <path d={BODY} />
      <circle cx="10.5" cy="7.9" r=".6" fill="var(--mark-eye, #fff)" />
      <g transform="matrix(-1 0 0 1 32 0)">
        <path d={BODY} />
        <circle cx="10.5" cy="7.9" r=".6" fill="var(--mark-eye, #fff)" />
      </g>
      <circle cx="16" cy="17.4" r="2.3" />
      <path d="M15.1 18.8h1.8l.6 4.4h-3z" />
    </svg>
  );
}
