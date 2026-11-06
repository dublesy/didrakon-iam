import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { Card, Field, Input, Loading, Mono, PageHeader, SourceStamp, Table } from "@/components/ui";
import { callIam } from "@/lib/iam-api";
import { changeOwnPassword } from "./me-actions";

type Assignment = {
  assignmentId: number;
  roleId: number;
  scopeId: number;
  sourceType: string;
  validFrom: string;
  validUntil: string | null;
  reviewRequired: boolean;
  roleCode: string | null;
  roleName: string | null;
  scopeCode: string | null;
  scopeName: string | null;
};

type Me = { subjectId: number; authenticationMethods: string[]; assignments: Assignment[] };

const METHOD_LABELS: Record<string, string> = { pwd: "비밀번호", otp: "인증 앱(TOTP)", hwk: "패스키", user: "사용자 확인" };

export default function Home() {
  return (
    <>
      <PageHeader title="내 정보" />
      <Suspense fallback={<Loading />}>
        <MyAccount />
      </Suspense>
    </>
  );
}

/** 세션을 읽으므로 Suspense 안에서 요청마다 그린다 */
async function MyAccount() {
  const result = await callIam<Me>("/api/v1/me");
  if (!result.ok) {
    return <p role="alert" className="text-danger">정보를 불러오지 못했습니다: {result.message}</p>;
  }
  const me = result.data;
  // 인증 앱(otp) 또는 패스키(hwk)
  const mfaDone = me.authenticationMethods.some((m) => m === "otp" || m === "hwk");

  return (
    <div className="space-y-6">
      {!mfaDone && (
        <div role="status" className="rounded-xl bg-warning-soft p-5 text-warning">
          관리 기능은 2단계 인증을 거친 로그인에서만 쓸 수 있습니다.{" "}
          <Link href="/mfa" className="font-medium underline underline-offset-2">
            인증 앱을 등록
          </Link>
          한 뒤 다시 로그인하세요.
        </div>
      )}

      <Card title="기본 정보">
        <dl className="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-2">
          <dt className="text-ink-3">Subject ID</dt>
          <dd>
            <Mono>{me.subjectId}</Mono>
          </dd>
          <dt className="text-ink-3">로그인 방법</dt>
          <dd className="text-ink">{me.authenticationMethods.map((m) => METHOD_LABELS[m] ?? m).join(" + ")}</dd>
        </dl>
      </Card>

      <Card title="비밀번호 변경">
        <p className="mb-4 text-sm text-ink-3">비밀번호를 바꾸면 이 콘솔을 포함해 모든 기기에서 로그아웃됩니다. 바꾼 뒤 새 비밀번호로 다시 로그인하세요</p>
        <ActionForm action={changeOwnPassword} submitLabel="바꾸기" resetOnSuccess>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-3">
            <Field label="현재 비밀번호" hint="틀리면 로그인 실패로 셉니다">
              <Input name="currentPassword" type="password" required autoComplete="current-password" />
            </Field>
            <Field label="새 비밀번호" hint="10자 이상, 로그인 ID 포함 불가">
              <Input name="newPassword" type="password" required minLength={10} autoComplete="new-password" />
            </Field>
            <Field label="새 비밀번호 확인">
              <Input name="confirmPassword" type="password" required minLength={10} autoComplete="new-password" />
            </Field>
          </div>
        </ActionForm>
      </Card>

      <Card title="보유 역할">
        <Table headers={["역할", "범위", "출처", "만료"]} empty={me.assignments.length === 0} emptyText="부여된 역할이 없습니다">
          {me.assignments.map((a) => (
            <tr key={a.assignmentId}>
              <td>
                {a.roleName ? (
                  <span className="font-medium text-ink">
                    {a.roleName} <Mono>({a.roleCode})</Mono>
                  </span>
                ) : (
                  <Mono>{a.roleId}</Mono>
                )}
              </td>
              <td>{a.scopeName ?? <Mono>{a.scopeId}</Mono>}</td>
              <td>
                <SourceStamp source={a.sourceType} />
              </td>
              <td className="font-mono tabular-nums text-ink-2">{a.validUntil ? new Date(a.validUntil).toLocaleString("ko-KR") : "없음"}</td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
