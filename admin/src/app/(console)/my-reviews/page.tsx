import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { Badge, Card, Field, Input, Loading, Mono, PageHeader, SourceStamp, Table } from "@/components/ui";
import { formatTime, query } from "@/lib/queries";
import type { MyAccessReviewItem } from "@/lib/types";
import { decideMyReview } from "./actions";

export default function MyReviewsPage() {
  return (
    <>
      <PageHeader
        title="내 검토 할 일"
        description="내가 관리하는 조직 구성원의 역할을 계속 둘지 정합니다. 유지하면 그대로 두고, 회수하면 바로 권한이 사라집니다. 기한까지 정하지 않으면 캠페인에 정한 처리가 적용됩니다"
      />
      <Suspense fallback={<Loading />}>
        <PendingReviews />
      </Suspense>
    </>
  );
}

async function PendingReviews() {
  const rows = await query<MyAccessReviewItem[]>("/api/v1/me/access-reviews", "/my-reviews");

  return (
    <Card>
      <Table headers={["캠페인", "대상자", "역할", "범위", "출처", "결정"]} empty={rows.length === 0} emptyText="검토할 항목이 없습니다">
        {rows.map(({ campaignName, dueAt, item: i }) => (
          <tr key={i.itemId} className="[&>td]:py-3 [&>td]:align-top">
            <td>
              <div className="font-medium">{campaignName}</div>
              <div className="text-xs text-ink-3 tabular-nums">기한 {formatTime(dueAt)}</div>
              {i.escalatedAt && (
                <div className="mt-1 text-xs text-ink-3">
                  <Badge tone="amber">이관</Badge> {i.escalatedFromName ?? "관리자"} 기한 경과
                </div>
              )}
            </td>
            <td>
              <div>{i.subjectName}</div>
              {i.empNo && <Mono>{i.empNo}</Mono>}
            </td>
            <td>
              <span className="flex flex-wrap items-center gap-1.5">
                {i.roleName}
                {i.isPrivileged && <Badge tone="red">특권</Badge>}
                {i.reviewRequired && <Badge tone="amber">재검토 표시</Badge>}
              </span>
            </td>
            <td>
              <Mono>{i.scopeName}</Mono>
            </td>
            <td>
              <SourceStamp source={i.sourceType} />
            </td>
            <td>
              <div className="flex flex-col gap-3">
                <ActionForm action={decideMyReview} submitLabel="유지" variant="subtle">
                  <input type="hidden" name="itemId" value={i.itemId} />
                  <input type="hidden" name="decision" value="KEEP" />
                  <Field label="의견 (선택)">
                    <Input name="comment" maxLength={1000} />
                  </Field>
                </ActionForm>
                <ActionForm
                  action={decideMyReview}
                  submitLabel="회수"
                  variant="danger"
                  confirmMessage={`${i.subjectName} 의 '${i.roleName}' 역할을 지금 회수할까요?`}
                >
                  <input type="hidden" name="itemId" value={i.itemId} />
                  <input type="hidden" name="decision" value="REVOKE" />
                  <Field label="회수 사유 (선택)">
                    <Input name="comment" maxLength={1000} />
                  </Field>
                </ActionForm>
              </div>
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
