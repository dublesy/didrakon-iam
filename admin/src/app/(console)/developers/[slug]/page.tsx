import Link from "next/link";
import { notFound } from "next/navigation";
import { Suspense } from "react";
import { Markdown } from "@/components/markdown";
import { Card, Loading, PageHeader, buttonClass } from "@/components/ui";
import { GUIDES, readGuide, titleOf } from "@/lib/developer-docs";

export function generateStaticParams() {
  return GUIDES.map((guide) => ({ slug: guide.slug }));
}

/** 스택별 가이드 한 편 */
export default function GuidePage({ params }: PageProps<"/developers/[slug]">) {
  return (
    <Suspense fallback={<Loading />}>
      <Guide params={params} />
    </Suspense>
  );
}

async function Guide({ params }: { params: PageProps<"/developers/[slug]">["params"] }) {
  const { slug } = await params;
  const source = await readGuide(slug);
  if (source === null) notFound();
  return (
    <>
      <PageHeader title={titleOf(source) ?? slug}>
        <Link href="/developers" className={buttonClass.secondary}>
          연동 가이드 목록
        </Link>
      </PageHeader>
      <Card>
        <Markdown source={source} />
      </Card>
    </>
  );
}
