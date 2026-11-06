import "server-only";
import { readFile } from "node:fs/promises";
import path from "node:path";
import { cacheLife } from "next/cache";

/**
 * 개발자 연동 가이드. 원본은 저장소의 docs/integration/*.md 이고 콘솔은 그대로 보여 준다 (문서를 한 곳에서만 고친다).
 * 문서가 가리키는 예제 소스(examples/integration/...)도 함께 보여 준다. 읽을 수 있는 파일은 아래 목록과 문서의 링크로 정해진다.
 */
const REPO_ROOT = path.resolve(process.cwd(), "..");
const DOCS_DIR = "docs/integration";

/** 화면 순서. slug 는 주소, file 은 docs/integration 안의 파일 */
export const GUIDES = [
  { slug: "spring-boot", file: "spring-boot.md", label: "Spring Boot" },
  { slug: "express", file: "express.md", label: "Node.js · Express" },
  { slug: "nextjs", file: "nextjs.md", label: "Next.js" },
  { slug: "python", file: "python.md", label: "Python" },
  { slug: "go", file: "go.md", label: "Go" },
  { slug: "rust", file: "rust.md", label: "Rust" },
  { slug: "php", file: "php.md", label: "PHP" },
  { slug: "dotnet", file: "dotnet.md", label: ".NET" },
  { slug: "ruby", file: "ruby.md", label: "Ruby" },
  { slug: "proxy", file: "proxy.md", label: "코드를 못 고치는 시스템 (프록시)" },
  { slug: "database", file: "database.md", label: "DB 계정 이관" },
] as const;

export type GuideSlug = (typeof GUIDES)[number]["slug"];

const INDEX_FILE = "README.md";

export async function readIndex(): Promise<string> {
  "use cache";
  cacheLife("max");
  return readFile(path.join(REPO_ROOT, DOCS_DIR, INDEX_FILE), "utf8");
}

export async function readGuide(slug: string): Promise<string | null> {
  "use cache";
  cacheLife("max");
  const guide = GUIDES.find((g) => g.slug === slug);
  return guide ? readFile(path.join(REPO_ROOT, DOCS_DIR, guide.file), "utf8") : null;
}

const EXAMPLES_PREFIX = "examples/integration/";

/**
 * 문서가 링크한 예제 경로(examples/integration/ 기준). 파일과 폴더(끝이 /)를 나눈다.
 * 이 목록 밖의 파일은 읽지 않는다
 */
export async function linkedExamples(): Promise<{ files: string[]; dirs: string[] }> {
  "use cache";
  cacheLife("max");
  const docs = await Promise.all([readIndex(), ...GUIDES.map((g) => readGuide(g.slug))]);
  const files = new Set<string>();
  const dirs = new Set<string>();
  for (const doc of docs) {
    for (const [, href] of (doc ?? "").matchAll(/\]\(([^)\s]+)\)/g)) {
      const target = repoPath(href);
      if (!target?.startsWith(EXAMPLES_PREFIX)) continue;
      const relative = target.slice(EXAMPLES_PREFIX.length);
      if (relative === "" || relative.endsWith("/")) dirs.add(relative.replace(/\/$/, ""));
      else files.add(relative);
    }
  }
  return { files: [...files].sort(), dirs: [...dirs].sort() };
}

/** 예제 파일 내용. 문서에 링크된 파일이 아니면 null */
export async function readExample(relative: string): Promise<string | null> {
  "use cache";
  cacheLife("max");
  if (!(await linkedExamples()).files.includes(relative)) return null;
  return readFile(path.join(REPO_ROOT, EXAMPLES_PREFIX, relative), "utf8");
}

/** docs/integration 기준 상대 링크를 저장소 루트 기준 경로로. 저장소 밖이나 바깥 주소면 null */
function repoPath(href: string): string | null {
  if (/^[a-z]+:/i.test(href) || href.startsWith("#")) return null;
  const normalized = path.posix.normalize(path.posix.join(DOCS_DIR, href.split("#")[0]));
  return normalized.startsWith("..") ? null : normalized;
}

/**
 * 문서 안 링크를 콘솔 주소로 바꾼다.
 * - 다른 가이드(go.md) → /developers/go, 첫 문서(README.md) → /developers, 문서 안 앵커는 그대로
 * - 예제 소스·폴더 → /developers/source/...
 * - 바깥 주소 → 그대로 (새 탭)
 * - 그 밖의 저장소 파일 → null (링크 없이 글자만)
 */
export function resolveDocHref(href: string): { href: string; external: boolean } | null {
  if (/^https?:/i.test(href)) return { href, external: true };
  if (href.startsWith("#")) return { href, external: false };
  const [file, hash] = href.split("#");
  const anchor = hash ? `#${hash}` : "";
  const target = repoPath(file);
  if (target === `${DOCS_DIR}/${INDEX_FILE}`) return { href: `/developers${anchor}`, external: false };
  const guide = GUIDES.find((g) => target === `${DOCS_DIR}/${g.file}`);
  if (guide) return { href: `/developers/${guide.slug}${anchor}`, external: false };
  if (target?.startsWith(EXAMPLES_PREFIX)) {
    const relative = target.slice(EXAMPLES_PREFIX.length).replace(/\/$/, "");
    return { href: relative ? `/developers/source/${relative}` : "/developers/source", external: false };
  }
  return null;
}

/** GitHub 과 같은 방식의 제목 앵커. 문서 안 링크(#5-계정-연결)가 그대로 맞는다 */
export function headingId(text: string): string {
  return text.trim().toLowerCase().replace(/[^\p{L}\p{N}\s-]/gu, "").replace(/\s/g, "-");
}

/** 첫 # 제목 */
export function titleOf(markdown: string): string | null {
  return markdown.match(/^#\s+(.+)$/m)?.[1]?.trim() ?? null;
}
