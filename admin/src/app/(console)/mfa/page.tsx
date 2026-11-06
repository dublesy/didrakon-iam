import { Suspense } from "react";
import { RowAction } from "@/components/action-form";
import { buttonClass, Card, Loading, PageHeader, Table } from "@/components/ui";
import { config } from "@/lib/config";
import { formatTime, query } from "@/lib/queries";
import type { MfaMethod, Passkey } from "@/lib/types";
import { removeMfaMethod, removePasskey } from "./actions";
import { MfaEnrollment } from "./mfa-enrollment";

export const metadata = { title: "2단계 인증 · DIDRAKON IAM" };

export default function MfaPage() {
  return (
    <>
      <PageHeader
        title="2단계 인증"
        description="로그인할 때 비밀번호 다음에 인증 앱의 6자리 코드를 입력하거나, 패스키로 로그인합니다. 관리 기능은 2단계 인증을 거친 로그인에서만 쓸 수 있습니다."
      />
      <Suspense fallback={<Loading />}>
        <Methods />
      </Suspense>
    </>
  );
}

async function Methods() {
  const [methods, passkeys] = await Promise.all([
    query<MfaMethod[]>("/api/v1/me/mfa", "/mfa"),
    query<Passkey[]>("/api/v1/me/passkeys", "/mfa"),
  ]);
  const last = methods.length === 1;

  return (
    <div className="space-y-6">
      <Card title="등록한 인증 앱">
        <Table headers={["", "등록", "마지막 사용", ""]} empty={methods.length === 0} emptyText="아직 등록한 인증 앱이 없습니다">
          {methods.map((m, i) => (
            <tr key={m.methodId}>
              <td className="font-medium">인증 앱 {i + 1}</td>
              <td>{formatTime(m.registeredAt)}</td>
              <td>{formatTime(m.lastUsedAt)}</td>
              <td className="text-right">
                <RowAction
                  action={removeMfaMethod}
                  label="삭제"
                  hidden={{ methodId: m.methodId }}
                  confirmMessage={
                    last
                      ? "마지막 인증 앱입니다. 삭제하면 다음 로그인부터 관리 기능을 쓸 수 없습니다. 삭제할까요?"
                      : "이 인증 앱을 삭제할까요? 그 앱의 코드로는 더 로그인할 수 없습니다"
                  }
                />
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      <MfaEnrollment hasMethods={methods.length > 0} />
      <Card
        title="패스키"
        actions={
          // 등록은 IAM 화면에서 한다 (브라우저의 패스키는 IAM 주소에 묶인다). 인증 앱을 거친 로그인이 필요하다
          <a href={`${config.issuer}/account/passkeys`} target="_blank" rel="noopener noreferrer" className={buttonClass.secondary}>
            패스키 추가
          </a>
        }
      >
        <p className="mb-4 text-sm text-ink-3">
          비밀번호 대신 기기의 생체 인증·PIN·보안 키로 로그인합니다. 패스키 로그인은 2단계 인증을 거친 것으로 봅니다. 추가하려면 먼저 인증 앱을 등록하세요.
        </p>
        <Table headers={["이름", "등록", "마지막 사용", ""]} empty={passkeys.length === 0} emptyText="아직 등록한 패스키가 없습니다">
          {passkeys.map((p) => (
            <tr key={p.credentialId}>
              <td className="font-medium">{p.label}</td>
              <td>{formatTime(p.createdAt)}</td>
              <td>{formatTime(p.lastUsedAt)}</td>
              <td className="text-right">
                <RowAction
                  action={removePasskey}
                  label="삭제"
                  hidden={{ credentialId: p.credentialId }}
                  confirmMessage="이 패스키를 삭제할까요? 그 기기로는 패스키 로그인을 할 수 없습니다"
                />
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}
