import { Suspense } from "react";
import { Badge, Card, Loading, Mono, PageHeader, Table } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query, subjectNames } from "@/lib/queries";
import { HR_SYNC_ACTIONS, type HrSyncRun } from "@/lib/types";
import { HrSyncForm } from "./hr-sync-form";

const REQUEST_EXAMPLE = `POST /api/v1/hr/sync?dryRun=true
{
  "employees": [
    { "empNo": "E1001", "name": "홍길동", "email": "hong@example.com", "phone": "010-0000-0000",
      "hireDate": "2024-03-02", "orgCode": "DEV-TEAM", "jobTitle": "팀장", "jobGrade": "G3",
      "isManager": true, "employmentStatus": "EMPLOYED", "retireDate": null }
  ],
  "reportMissing": true
}`;

export default function HrSyncPage() {
  return (
    <>
      <PageHeader
        title="HR 연동"
        description="인사 시스템을 원본으로 입사·이동·휴직·퇴사를 사번 기준으로 맞춥니다. 레코드마다 따로 처리하므로 한 명이 실패해도 나머지는 반영됩니다."
      />
      <div className="space-y-6">
        <Card title="호출 방법">
          <div className="space-y-4 text-ink-2">
            <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
              <dt className="text-ink-3">주소</dt>
              <dd>
                <Mono>POST /api/v1/hr/sync?dryRun=true|false</Mono> (dryRun 은 꼭 넣습니다. true 면 결과만 계산하고 반영하지 않습니다)
              </dd>
              <dt className="text-ink-3">인증</dt>
              <dd>
                <Mono>iam.hr.sync</Mono> scope 를 가진 client credentials 토큰, 또는 <Mono>IAM_HR_SYNC</Mono> 역할을 준 서비스 계정의 API 키(
                <Mono>X-API-Key</Mono> 헤더)
              </dd>
              <dt className="text-ink-3">실행 기록</dt>
              <dd>
                <Mono>GET /api/v1/hr/sync-runs</Mono> (최근 50건)
              </dd>
            </dl>
            <ul className="list-disc space-y-1 pl-5">
              <li>처음 보는 사번은 사용자와 주 소속을 만듭니다. 로그인 계정은 만들지 않으므로 따로 발급하거나 SSO 로 연결합니다</li>
              <li>주 소속 조직이 바뀌면 소속 이동(전적·전보)으로 처리되어 권한이 정리됩니다. 빈 선택 항목은 기존 값을 그대로 둡니다</li>
              <li>휴직(LEAVE)이면 사용 안 함이 되어 세션·토큰·API 키가 회수되고, 재직(EMPLOYED)이면 다시 사용으로 바뀝니다. 재직 상태의 원본은 인사 시스템이므로 콘솔에서 사용 중지한 사람도 다음 연동에서 재직이면 다시 사용됩니다</li>
              <li>퇴사(RETIRED)나 퇴사일이 오면 퇴사 처리하고, 미래 날짜면 예약합니다. 목록에 없는 사람은 알려주기만 하고 퇴사시키지 않습니다</li>
            </ul>
            <pre className="overflow-x-auto rounded-lg bg-panel p-4 font-mono text-[12px] text-ink-2">{REQUEST_EXAMPLE}</pre>
          </div>
        </Card>

        <Card title="직접 실행">
          <HrSyncForm />
        </Card>

        <Suspense fallback={<Loading />}>
          <RunList />
        </Suspense>
      </div>
    </>
  );
}

async function RunList() {
  const runs = await query<HrSyncRun[]>("/api/v1/hr/sync-runs", "/hr-sync");
  const names = await subjectNames(runs.flatMap((r) => (r.actorSubjectId === null ? [] : [r.actorSubjectId])), "/hr-sync");

  return (
    <Card title="최근 실행">
      <Table headers={["시각", "방식", "실행자", "레코드", "결과", "목록에 없음", "오류"]} empty={runs.length === 0} emptyText="아직 실행한 적이 없습니다">
        {runs.map((run) => (
          <tr key={run.runId}>
            <td className="whitespace-nowrap tabular-nums">{formatTime(run.startedAt)}</td>
            <td>{run.dryRun ? <Badge>미리보기</Badge> : <Badge tone="blue">반영</Badge>}</td>
            <td className="text-ink-2">{run.actorSubjectId === null ? "연동 클라이언트" : (names.get(run.actorSubjectId) ?? run.actorSubjectId)}</td>
            <td className="tabular-nums">{run.total}</td>
            <td className="text-ink-2">
              {HR_SYNC_ACTIONS.filter((a) => a !== "ERROR" && run.counts[a])
                .map((a) => `${label("hrAction", a)} ${run.counts[a]}`)
                .join(" · ") || "—"}
            </td>
            <td className="tabular-nums">{run.missingCount ?? "—"}</td>
            <td className="align-top">
              {run.errors.length === 0 ? (
                <span className="text-ink-3">없음</span>
              ) : (
                <details className="py-2">
                  <summary className="cursor-pointer text-danger">{run.counts.ERROR ?? run.errors.length}건</summary>
                  <ul className="mt-2 space-y-1 text-xs">
                    {run.errors.map((e, i) => (
                      <li key={`${e.empNo}-${i}`}>
                        <Mono>{e.empNo ?? "—"}</Mono> <span className="text-ink-2">{e.message}</span>
                      </li>
                    ))}
                  </ul>
                </details>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
