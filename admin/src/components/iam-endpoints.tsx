import { connection } from "next/server";
import { CopyButton } from "@/components/copy-button";
import { config } from "@/lib/config";
import type { Client } from "@/lib/types";

type Row = { label: string; value: string; hint?: string };

/** 값과 복사 버튼을 한 줄씩 */
export function CopyRows({ rows }: { rows: Row[] }) {
  return (
    <dl className="divide-y divide-line">
      {rows.map((row) => (
        <div key={`${row.label} ${row.value}`} className="grid grid-cols-[10rem_minmax(0,1fr)_auto] items-center gap-3 py-2">
          <dt className="text-ink-2">{row.label}</dt>
          <dd className="min-w-0">
            <span className="block break-all font-mono text-[12px] text-ink">{row.value}</span>
            {row.hint && <span className="text-[12px] text-ink-3">{row.hint}</span>}
          </dd>
          <CopyButton value={row.value} label={row.label} />
        </div>
      ))}
    </dl>
  );
}

/** 지금 이 IAM 의 OIDC 주소. 배포마다 다르므로 요청 때 설정에서 읽는다 */
export async function IamEndpoints() {
  await connection();
  const issuer = config.issuer.replace(/\/$/, "");
  return (
    <CopyRows
      rows={[
        { label: "Issuer", value: issuer, hint: "토큰 iss. 대부분 라이브러리는 이 값 하나로 나머지를 찾는다" },
        { label: "Discovery", value: `${issuer}/.well-known/openid-configuration` },
        { label: "Authorize", value: `${issuer}/oauth2/authorize` },
        { label: "Token", value: `${issuer}/oauth2/token` },
        { label: "JWKS", value: `${issuer}/oauth2/jwks`, hint: "토큰 서명 검증 키" },
        { label: "UserInfo", value: `${issuer}/userinfo` },
        { label: "Logout", value: `${issuer}/connect/logout`, hint: "RP 로그아웃 (id_token_hint, post_logout_redirect_uri)" },
      ]}
    />
  );
}

/** 클라이언트 하나의 연동 값과 등록된 로그인 설정 */
export async function ClientConnection({ client }: { client: Client }) {
  await connection();
  const issuer = config.issuer.replace(/\/$/, "");
  return (
    <CopyRows
      rows={[
        { label: "Issuer", value: issuer },
        {
          label: "Client ID",
          value: client.clientCode,
          hint: client.confidential
            ? "기밀 클라이언트 (client_secret_basic). 비밀값(client_secret)은 등록·재발급할 때 한 번만 보여 줍니다"
            : "공개 클라이언트. 비밀값 없이 PKCE 를 씁니다",
        },
        { label: "Discovery", value: `${issuer}/.well-known/openid-configuration` },
        ...client.redirectUris.map((uri) => ({ label: "Redirect URI", value: uri })),
        ...client.postLogoutRedirectUris.map((uri) => ({ label: "로그아웃 뒤 주소", value: uri, hint: "post_logout_redirect_uri" })),
        ...(client.scopes.length > 0 ? [{ label: "Scope", value: client.scopes.join(" ") }] : []),
        ...(client.backchannelLogoutUri
          ? [{ label: "로그아웃 알림 주소", value: client.backchannelLogoutUri, hint: "IAM 이 로그아웃 토큰을 보내는 이 시스템의 주소" }]
          : []),
      ]}
    />
  );
}
