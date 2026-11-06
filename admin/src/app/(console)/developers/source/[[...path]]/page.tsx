import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { Card, Loading, PageHeader, buttonClass } from "@/components/ui";
import { linkedExamples, readExample } from "@/lib/developer-docs";

export async function generateStaticParams() {
  const { files, dirs } = await linkedExamples();
  return [...files, ...dirs].map((p) => ({ path: p === "" ? [] : p.split("/") }));
}

const BackToGuides = () => (
  <Link href="/developers" className={buttonClass.secondary}>
    연동 가이드 목록
  </Link>
);

/**
 * 가이드가 가리키는 예제 앱 소스. 가이드에 링크된 파일만 보여 준다.
 * 폴더 주소면 그 아래의 링크된 파일 목록을 보여 준다
 */
export default function SourcePage({ params }: PageProps<"/developers/source/[[...path]]">) {
  return (
    <Suspense fallback={<Loading />}>
      <Source params={params} />
    </Suspense>
  );
}

async function Source({ params }: { params: PageProps<"/developers/source/[[...path]]">["params"] }) {
  const segments = ((await params).path ?? []).map(decodeURIComponent);
  const relative = segments.join("/");
  const source = relative ? await readExample(relative) : null;

  if (source !== null) {
    return (
      <>
        <PageHeader title={relative} description="예제 앱 소스. 실제로 이 IAM 에 붙여 검증한 코드입니다">
          <BackToGuides />
        </PageHeader>
        <Card>
          <pre className="overflow-x-auto font-mono text-[12.5px] leading-relaxed text-ink">
            <code>{source}</code>
          </pre>
        </Card>
      </>
    );
  }

  const { files } = await linkedExamples();
  const inside = files.filter((f) => relative === "" || f.startsWith(`${relative}/`));
  if (inside.length === 0) notFound();
  return (
    <>
      <PageHeader title={relative ? `${relative} 예제` : "예제 앱"} description="스택마다 같은 기능(로그인·내 정보·로그아웃·back-channel 로그아웃·웹훅)을 구현한 예제입니다. 가이드에서 설명하는 파일을 모았습니다">
        <BackToGuides />
      </PageHeader>
      <Card>
        <ul className="divide-y divide-line">
          {inside.map((file) => (
            <li key={file}>
              <Link href={`/developers/source/${file}`} className="flex h-10 items-center font-mono text-[12.5px] text-ink hover:text-accent">
                {file}
              </Link>
            </li>
          ))}
        </ul>
      </Card>
    </>
  );
}
