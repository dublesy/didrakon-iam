import Link from "next/link";
import { Suspense } from "react";
import { IamEndpoints } from "@/components/iam-endpoints";
import { Markdown } from "@/components/markdown";
import { Card, Loading, PageHeader } from "@/components/ui";
import { GUIDES, readIndex } from "@/lib/developer-docs";

/** 개발자 연동 가이드 첫 화면: 이 IAM 의 주소, 스택별 가이드, 공통 연동 방법 */
export default async function DevelopersPage() {
  const index = await readIndex();
  return (
    <>
      <PageHeader
        title="연동 가이드"
        description="다른 시스템을 이 IAM 에 붙이는 개발자용 안내. 표준 OIDC 라서 HTTP 를 보내고 JWT 서명을 검증할 수 있으면 어떤 언어든 붙일 수 있습니다"
      />
      <div className="space-y-6">
        <Card title="이 IAM 의 주소">
          <Suspense fallback={<Loading />}>
            <IamEndpoints />
          </Suspense>
        </Card>
        <Card title="스택별 가이드">
          <ul className="grid grid-cols-2 gap-2 md:grid-cols-3">
            {GUIDES.map((guide) => (
              <li key={guide.slug}>
                <Link
                  href={`/developers/${guide.slug}`}
                  className="flex h-10 items-center rounded-lg border border-line px-3 font-medium text-ink transition-colors hover:border-accent hover:text-accent"
                >
                  {guide.label}
                </Link>
              </li>
            ))}
          </ul>
        </Card>
        <Card>
          <Markdown source={index} />
        </Card>
      </div>
    </>
  );
}
