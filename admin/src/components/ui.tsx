import type { ComponentProps, ReactNode } from "react";
import { SOURCE_LABELS } from "@/lib/labels";

/** 관리 화면 공통 요소. 모양의 기준은 admin/DESIGN.md */

export function PageHeader({ title, description, children }: { title: string; description?: string; children?: ReactNode }) {
  return (
    <header className="mb-6 flex flex-wrap items-end justify-between gap-4">
      <div className="min-w-0">
        <h1 className="text-xl font-semibold text-ink">{title}</h1>
        {description && <p className="mt-1 max-w-[70ch] text-ink-3">{description}</p>}
      </div>
      {children && <div className="flex items-center gap-2">{children}</div>}
    </header>
  );
}

/**
 * 버튼 모양 기준. 링크(<Link>)든 버튼이든 같은 모양이 필요하면 이 값을 className 으로 쓴다.
 * primary: 화면의 주 작업 하나, secondary: 목록·닫기 같은 보조, row: 표 안의 작은 작업
 */
export const buttonClass = {
  primary:
    "inline-flex h-9 items-center justify-center rounded-lg bg-accent px-3.5 font-medium text-white transition-colors hover:bg-accent-hover disabled:cursor-wait disabled:opacity-60",
  danger:
    "inline-flex h-9 items-center justify-center rounded-lg bg-danger px-3.5 font-medium text-white transition-colors hover:opacity-90 disabled:cursor-wait disabled:opacity-60",
  secondary:
    "inline-flex h-9 items-center justify-center rounded-lg border border-line-strong bg-surface px-3 font-medium text-ink transition-colors hover:bg-panel disabled:cursor-wait disabled:opacity-60",
  row: "inline-flex h-7 items-center whitespace-nowrap rounded-md border border-line-strong bg-surface px-2 text-xs font-medium text-ink-2 transition-colors hover:bg-panel hover:text-ink disabled:opacity-60",
  rowDanger:
    "inline-flex h-7 items-center whitespace-nowrap rounded-md border border-line-strong bg-surface px-2 text-xs font-medium text-danger transition-colors hover:border-danger hover:bg-danger-soft disabled:opacity-60",
} as const;

/** 표·폼이 놓이는 면. 그림자 없이 헤어라인으로 구분한다 */
export function Card({ title, children, className = "", actions }: { title?: string; children: ReactNode; className?: string; actions?: ReactNode }) {
  return (
    <section className={`rounded-xl border border-line bg-surface p-5 ${className}`}>
      {(title || actions) && (
        <div className="mb-4 flex items-center justify-between gap-3">
          {title && <h2 className="text-base font-semibold text-ink">{title}</h2>}
          {actions}
        </div>
      )}
      {children}
    </section>
  );
}

/** 생성 폼을 늘 펼쳐 두지 않고 버튼으로 연다 */
export function AddPanel({ label, children }: { label: string; children: ReactNode }) {
  return (
    <details className="group rounded-xl border border-line bg-surface open:p-5 [&:not([open])]:border-0 [&:not([open])]:bg-transparent">
      <summary className="inline-flex h-9 cursor-pointer list-none items-center gap-1.5 rounded-lg bg-accent px-3 font-medium text-white transition-colors hover:bg-accent-hover group-open:mb-4 group-open:bg-transparent group-open:px-0 group-open:text-ink group-open:hover:bg-transparent [&::-webkit-details-marker]:hidden">
        <svg aria-hidden viewBox="0 0 16 16" className="size-4 transition-transform motion-reduce:transition-none group-open:rotate-45" fill="none" stroke="currentColor" strokeWidth="1.5">
          <path d="M8 3v10M3 8h10" />
        </svg>
        <span className="group-open:hidden">{label}</span>
        <span className="hidden text-base font-semibold group-open:inline">{label}</span>
      </summary>
      {children}
    </details>
  );
}

export function Table({ headers, children, empty, emptyText = "아직 항목이 없습니다" }: {
  headers: string[];
  children: ReactNode;
  empty?: boolean;
  emptyText?: string;
}) {
  if (empty) return <p className="py-6 text-center text-ink-3">{emptyText}</p>;
  return (
    <div className="-mx-5 overflow-x-auto">
      <table className="w-full text-left text-[13px]">
        <thead className="border-y border-line bg-panel text-ink-3">
          <tr>
            {headers.map((h, i) => (
              <th key={`${h}-${i}`} className="h-9 px-5 font-medium whitespace-nowrap first:pl-5 [&:not(:first-child)]:pl-3">
                {h}
              </th>
            ))}
          </tr>
        </thead>
        <tbody className="[&>tr]:border-b [&>tr]:border-line [&>tr:last-child]:border-0 [&>tr:hover]:bg-canvas [&_td]:h-10 [&_td]:px-3 [&_td]:align-middle [&_td:first-child]:pl-5 [&_td:last-child]:pr-5">
          {children}
        </tbody>
      </table>
    </div>
  );
}

export function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return (
    <label className="flex min-w-0 flex-col gap-1.5">
      <span className="text-[13px] font-medium text-ink-2">{label}</span>
      {children}
      {hint && <span className="text-xs text-ink-3">{hint}</span>}
    </label>
  );
}

const control =
  "h-9 rounded-lg border border-field-line bg-surface px-3 text-ink placeholder:text-ink-3 transition-colors hover:border-ink-3 focus:border-accent focus:outline-none focus-visible:outline-2 focus-visible:outline-offset-0 focus-visible:outline-accent disabled:bg-panel";

export const Input = (props: ComponentProps<"input">) => <input {...props} className={`${control} ${props.className ?? ""}`} />;

export const Select = (props: ComponentProps<"select">) => <select {...props} className={`${control} pr-8 ${props.className ?? ""}`} />;

export const Textarea = (props: ComponentProps<"textarea">) => (
  <textarea {...props} className={`${control} h-auto min-h-20 py-2 font-mono text-[13px] ${props.className ?? ""}`} />
);

export function Checkbox({ label, ...props }: ComponentProps<"input"> & { label: string }) {
  return (
    <label className="flex h-9 items-center gap-2 text-ink-2">
      <input type="checkbox" className="size-4" {...props} />
      {label}
    </label>
  );
}

type Tone = "zinc" | "green" | "red" | "amber" | "blue";

const tones: Record<Tone, string> = {
  zinc: "bg-panel text-ink-2",
  green: "bg-success-soft text-success",
  red: "bg-danger-soft text-danger",
  amber: "bg-warning-soft text-warning",
  blue: "bg-accent-soft text-accent",
};

/** 상태 표시. 색은 의미가 있을 때만 (DESIGN.md) */
export function Badge({ children, tone = "zinc" }: { children: ReactNode; tone?: Tone }) {
  return <span className={`inline-flex h-5 items-center rounded-md px-1.5 text-xs font-medium whitespace-nowrap ${tones[tone]}`}>{children}</span>;
}

/** 출처 표식: 권한이 어디서 왔는지. 이 제품의 고유 디테일이라 다른 용도로 쓰지 않는다 */
export function SourceStamp({ source }: { source: string }) {
  return (
    <span className="inline-flex h-5 items-center rounded border border-line-strong px-1.5 font-mono text-[11px] tracking-wide text-ink-2" title={`출처: ${SOURCE_LABELS[source] ?? source}`}>
      {SOURCE_LABELS[source] ?? source}
    </span>
  );
}

/** ID·trace 같은 기계 값 */
export const Mono = ({ children }: { children: ReactNode }) => <span className="font-mono text-[12px] text-ink-2">{children}</span>;

/** 목록·상세를 읽는 동안 자리만 잡아 둔다 */
export function Loading() {
  return (
    <div className="space-y-3 rounded-xl border border-line bg-surface p-5" aria-busy="true" aria-label="불러오는 중">
      {[60, 90, 75, 85].map((w) => (
        <div key={w} className="h-4 rounded bg-panel" style={{ width: `${w}%` }} />
      ))}
    </div>
  );
}

/** select 옵션용: enum 값 목록 */
export function Options({ values, labels }: { values: readonly string[]; labels?: Record<string, string> }) {
  return values.map((v) => (
    <option key={v} value={v}>
      {labels?.[v] ?? v}
    </option>
  ));
}
