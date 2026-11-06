import Link from "next/link";
import { Children, isValidElement, type ReactNode } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { headingId, resolveDocHref } from "@/lib/developer-docs";

/** 제목 글자만 뽑는다 (인라인 코드·강조가 섞여도) */
function textOf(node: ReactNode): string {
  return Children.toArray(node)
    .map((child) => {
      if (typeof child === "string" || typeof child === "number") return String(child);
      if (isValidElement<{ children?: ReactNode }>(child)) return textOf(child.props.children);
      return "";
    })
    .join("");
}

const components: Components = {
  // 문서의 # 제목은 화면 제목(PageHeader)으로 쓴다
  h1: () => null,
  h2: ({ children }) => (
    <h2 id={headingId(textOf(children))} className="mt-10 mb-3 scroll-mt-20 border-b border-line pb-2 text-base font-semibold text-ink first:mt-0">
      {children}
    </h2>
  ),
  h3: ({ children }) => (
    <h3 id={headingId(textOf(children))} className="mt-7 mb-2 scroll-mt-20 text-[14px] font-semibold text-ink">
      {children}
    </h3>
  ),
  a: ({ href, children }) => {
    const target = href ? resolveDocHref(href) : null;
    if (!target) return <span className="font-mono text-[12px] text-ink-2">{children}</span>;
    if (target.external) {
      return (
        <a href={target.href} target="_blank" rel="noreferrer" className="text-accent underline underline-offset-2 hover:text-accent-hover">
          {children}
        </a>
      );
    }
    return (
      <Link href={target.href} className="text-accent underline underline-offset-2 hover:text-accent-hover">
        {children}
      </Link>
    );
  },
  table: ({ children }) => (
    <div className="my-4 overflow-x-auto rounded-lg border border-line">
      <table className="w-full border-collapse text-[13px]">{children}</table>
    </div>
  ),
  th: ({ children }) => <th className="border-b border-line bg-panel px-3 py-2 text-left font-medium text-ink-2">{children}</th>,
  td: ({ children }) => <td className="border-b border-line px-3 py-2 align-top last:border-b-0">{children}</td>,
};

/**
 * 연동 가이드 문서 본문. 모양은 콘솔 토큰을 따른다 (admin/DESIGN.md).
 * 원문 HTML 은 그리지 않는다 (react-markdown 기본값).
 */
export function Markdown({ source }: { source: string }) {
  return (
    <div
      className={[
        "max-w-[86ch] text-[14px] leading-relaxed text-ink",
        "[&_p]:my-3 [&_ul]:my-3 [&_ul]:list-disc [&_ul]:pl-5 [&_ol]:my-3 [&_ol]:list-decimal [&_ol]:pl-5 [&_li]:my-1",
        "[&_strong]:font-semibold [&_hr]:my-8 [&_hr]:border-line",
        "[&_blockquote]:my-4 [&_blockquote]:border-l-2 [&_blockquote]:border-line-strong [&_blockquote]:pl-4 [&_blockquote]:text-ink-2",
        "[&_code]:rounded [&_code]:bg-panel [&_code]:px-1 [&_code]:py-0.5 [&_code]:font-mono [&_code]:text-[12.5px]",
        "[&_pre]:my-4 [&_pre]:overflow-x-auto [&_pre]:rounded-lg [&_pre]:border [&_pre]:border-line [&_pre]:bg-panel [&_pre]:p-4",
        "[&_pre_code]:bg-transparent [&_pre_code]:p-0 [&_pre_code]:text-[12.5px] [&_pre_code]:leading-relaxed",
        "[&_tbody_tr:last-child_td]:border-b-0",
      ].join(" ")}
    >
      <ReactMarkdown remarkPlugins={[remarkGfm]} components={components}>
        {source}
      </ReactMarkdown>
    </div>
  );
}
