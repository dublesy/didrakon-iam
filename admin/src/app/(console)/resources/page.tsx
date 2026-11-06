import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { ClientConnection } from "@/components/iam-endpoints";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, Table, Textarea, buttonClass } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { query } from "@/lib/queries";
import { ACTIONS, EFFECTS, RESOURCE_TYPES, SENSITIVITIES, type Client, type Permission, type Resource } from "@/lib/types";
import {
  changeClientActive,
  changePermissionActive,
  changeResourceActive,
  createPermission,
  createResource,
  registerClient,
  rotateClientSecret,
  updateClient,
  updatePermission,
  updateResource,
} from "./actions";

/** IAM 자체 클라이언트. 리소스는 기동 시 코드가 관리한다 */
const SYSTEM_CLIENT_CODE = "iam-admin";

const CLIENT_TYPES = ["WEB", "API", "MOBILE", "BATCH"] as const;

/** 사용자 로그인(authorization code) 클라이언트. 이것만 로그인 주소를 가진다 */
const userFacing = (c: Client) => c.clientType === "WEB" || c.clientType === "MOBILE";


const ActiveBadge = ({ active }: { active: boolean }) => (active ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>);

type Params = Awaited<PageProps<"/resources">["searchParams"]>;
const param = (params: Params, name: string) => Number(params[name]) || undefined;

export default function ResourcesPage({ searchParams }: PageProps<"/resources">) {
  return (
    <>
      <PageHeader title="리소스·권한" description="SSO 클라이언트별 리소스 트리와 리소스별 권한" />
      <div className="space-y-6">
        <AddPanel label="SSO 클라이언트 추가">
          <ActionForm action={registerClient} submitLabel="등록" resetOnSuccess>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="클라이언트 코드">
                <Input name="clientCode" required maxLength={100} />
              </Field>
              <Field label="이름">
                <Input name="clientName" required maxLength={200} />
              </Field>
              <Field label="유형">
                <Select name="clientType">
                  <Options values={CLIENT_TYPES} labels={LABELS.clientType} />
                </Select>
              </Field>
              <Field label="리다이렉트 URI" hint="한 줄에 하나">
                <Textarea name="redirectUris" rows={2} />
              </Field>
              <Field label="로그아웃 뒤 돌아갈 주소 (선택)" hint="한 줄에 하나. 앱이 IAM 로그아웃(/connect/logout)으로 보낼 때 쓰는 post_logout_redirect_uri">
                <Textarea name="postLogoutRedirectUris" rows={2} />
              </Field>
              <Field label="스코프" hint="공백으로 구분">
                <Input name="scopes" defaultValue="openid profile" />
              </Field>
              <Field label="앱 시작 주소 (선택)" hint="넣으면 IAM 홈의 '내 앱'에 바로가기로 나옵니다">
                <Input name="homeUrl" type="url" placeholder="https://app.example.com/" />
              </Field>
              <Field label="로그아웃 알림 주소 (선택)" hint="IAM 에서 로그아웃되면 이 주소로 로그아웃 토큰을 보냅니다">
                <Input name="backchannelLogoutUri" type="url" placeholder="https://app.example.com/backchannel-logout" />
              </Field>
              <div className="flex flex-col justify-center gap-2">
                <Checkbox name="confidential" label="기밀 클라이언트 (비밀값 발급)" defaultChecked />
                <Checkbox name="requireMfa" label="MFA 필수" />
                <Checkbox name="supabaseRoleClaim" label="Supabase 호환 (토큰에 role 넣기)" />
              </div>
            </div>
          </ActionForm>
        </AddPanel>
        <Suspense fallback={<Loading />}>
          <ResourceCatalog searchParams={searchParams} />
        </Suspense>
      </div>
    </>
  );
}

/**
 * 수정 폼의 로그인 설정 칸. 관리 콘솔 클라이언트는 바꾸면 모든 관리자가 로그인하지 못할 수 있어 서버가 막으므로 값만 보여 준다.
 * 시스템 간 호출 클라이언트는 로그인 주소가 없으므로 scope 만 둔다
 */
function ClientLoginFields({ client }: { client: Client }) {
  if (client.clientCode === SYSTEM_CLIENT_CODE) {
    return (
      <div className="col-span-2 text-ink-3 md:col-span-3">
        <p>로그인 설정은 바꿀 수 없습니다. 관리 콘솔이 로그인하는 주소라서 잘못 바꾸면 되돌릴 수 없습니다</p>
        <p className="mt-1 break-all font-mono text-[12px]">redirect URI: {client.redirectUris.join(" ")}</p>
        <p className="break-all font-mono text-[12px]">scope: {client.scopes.join(" ")}</p>
      </div>
    );
  }
  return (
    <>
      {userFacing(client) && (
        <>
          <Field label="리다이렉트 URI" hint="한 줄에 하나. 빼면 그 주소로는 바로 로그인할 수 없습니다">
            <Textarea name="redirectUris" rows={2} required defaultValue={client.redirectUris.join("\n")} />
          </Field>
          <Field label="로그아웃 뒤 돌아갈 주소" hint="한 줄에 하나">
            <Textarea name="postLogoutRedirectUris" rows={2} defaultValue={client.postLogoutRedirectUris.join("\n")} />
          </Field>
        </>
      )}
      <Field label="스코프" hint={userFacing(client) ? "공백으로 구분. openid·profile 은 늘 들어갑니다" : "공백으로 구분"}>
        <Input name="scopes" defaultValue={client.scopes.join(" ")} />
      </Field>
    </>
  );
}

/** 부모를 따라 깊이를 붙여 트리 순서로 편다. 부모가 목록에 없으면 최상위로 본다 */
function flatten(resources: Resource[]): { resource: Resource; depth: number }[] {
  const ids = new Set(resources.map((r) => r.resourceId));
  const children = new Map<number | null, Resource[]>();
  for (const r of resources) {
    const parent = r.parentResourceId !== null && ids.has(r.parentResourceId) ? r.parentResourceId : null;
    children.set(parent, [...(children.get(parent) ?? []), r]);
  }
  const walk = (parent: number | null, depth: number): { resource: Resource; depth: number }[] =>
    (children.get(parent) ?? []).flatMap((r) => [{ resource: r, depth }, ...walk(r.resourceId, depth + 1)]);
  return walk(null, 0);
}

async function ResourceCatalog({ searchParams }: { searchParams: PageProps<"/resources">["searchParams"] }) {
  const params = await searchParams;
  const clients = await query<Client[]>("/api/v1/clients", "/resources");
  const clientId = Number(params.clientId) || clients[0]?.clientId;
  const client = clients.find((c) => c.clientId === clientId);

  const resourceId = param(params, "resourceId");
  const here = `/resources?clientId=${clientId}${resourceId ? `&resourceId=${resourceId}` : ""}`;
  const editing = clients.find((c) => c.clientId === param(params, "editClient"));

  return (
    <>
      <Card title="SSO 클라이언트" actions={editing && <Link href={here} className="text-ink-2 hover:text-ink">닫기</Link>}>
        {editing && (
          <ActionForm key={editing.clientId} action={updateClient} submitLabel="저장" className="mb-5 border-b border-line pb-5">
            <input type="hidden" name="clientId" value={editing.clientId} />
            {resourceId && <input type="hidden" name="resourceId" value={resourceId} />}
            <p className="mb-4 text-ink-3">{editing.clientCode} 수정. 코드·유형·비밀값 유무는 바꿀 수 없습니다</p>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="이름">
                <Input name="clientName" required maxLength={200} defaultValue={editing.clientName} />
              </Field>
              <Field label="앱 시작 주소" hint="비우면 IAM 홈의 '내 앱'에 나오지 않습니다">
                <Input name="homeUrl" type="url" defaultValue={editing.homeUrl ?? ""} />
              </Field>
              <Field label="로그아웃 알림 주소" hint="비우면 보내지 않습니다">
                <Input name="backchannelLogoutUri" type="url" defaultValue={editing.backchannelLogoutUri ?? ""} />
              </Field>
              <div className="flex flex-col justify-end gap-2">
                <Checkbox name="requireMfa" label="MFA 필수" defaultChecked={editing.requireMfa} />
                <Checkbox name="supabaseRoleClaim" label="Supabase 호환 (토큰에 role 넣기)" defaultChecked={editing.supabaseRoleClaim} />
              </div>
              <ClientLoginFields client={editing} />
            </div>
          </ActionForm>
        )}
        <Table headers={["클라이언트 코드", "이름", "유형", "MFA", "상태", ""]} empty={clients.length === 0} emptyText="등록된 클라이언트가 없습니다">
          {clients.map((c) => (
            <tr key={c.clientId} className={c.clientId === clientId ? "bg-accent-soft" : c.isActive ? undefined : "text-ink-3"}>
              <td>
                <Link href={`/resources?clientId=${c.clientId}`} className="font-mono text-[12px] font-medium text-ink hover:text-accent">
                  {c.clientCode}
                </Link>
              </td>
              <td>{c.clientName}</td>
              <td>{label("clientType", c.clientType)}</td>
              <td>{c.requireMfa ? "필수" : ""}</td>
              <td>
                <ActiveBadge active={c.isActive} />
              </td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link href={`/resources?clientId=${c.clientId}&editClient=${c.clientId}`} className={buttonClass.row}>
                    수정
                  </Link>
                  {c.clientCode !== SYSTEM_CLIENT_CODE && (
                    <RowAction
                      action={changeClientActive}
                      label={c.isActive ? "끄기" : "켜기"}
                      tone={c.isActive ? "danger" : "neutral"}
                      hidden={{ clientId: c.clientId, active: String(!c.isActive) }}
                      confirmMessage={c.isActive ? "이 시스템으로 로그인과 토큰 발급이 막힙니다. 이미 발급된 토큰은 만료될 때까지 남습니다. 끌까요?" : undefined}
                    />
                  )}
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      {client && client.clientCode !== SYSTEM_CLIENT_CODE && (
        <Card
          title={`${client.clientCode} 연동 정보`}
          actions={
            <Link href="/developers" className="text-ink-2 hover:text-ink">
              연동 가이드
            </Link>
          }
        >
          <ClientConnection client={client} />
          {client.confidential && (
            <ActionForm
              key={client.clientId}
              action={rotateClientSecret}
              submitLabel="비밀값 재발급"
              variant="subtle"
              confirmMessage={`'${client.clientCode}' 의 비밀값(client_secret)을 다시 발급할까요? 이전 비밀값은 바로 쓸 수 없게 되므로 연동 시스템에도 새 값을 넣어야 합니다. 이미 발급된 토큰은 만료될 때까지 남습니다`}
            >
              <input type="hidden" name="clientId" value={client.clientId} />
              {resourceId && <input type="hidden" name="resourceId" value={resourceId} />}
            </ActionForm>
          )}
        </Card>
      )}
      {client && <ClientResources client={client} resourceId={resourceId} params={params} />}
    </>
  );
}

async function ClientResources({ client, resourceId, params }: { client: Client; resourceId?: number; params: Params }) {
  const here = `/resources?clientId=${client.clientId}`;
  const resources = await query<Resource[]>(`/api/v1/resources?clientId=${client.clientId}`, here);
  const tree = flatten(resources);
  const selected = resources.find((r) => r.resourceId === resourceId);
  const isSystem = client.clientCode === SYSTEM_CLIENT_CODE;
  const editing = resources.find((r) => r.resourceId === param(params, "editResource"));
  const selectedHere = `${here}${resourceId ? `&resourceId=${resourceId}` : ""}`;

  return (
    <>
      <AddPanel label="리소스 추가">
        <ActionForm action={createResource} submitLabel="리소스 추가" resetOnSuccess>
          <input type="hidden" name="clientId" value={client.clientId} />
          <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
            <Field label="리소스 키">
              <Input name="resourceKey" required maxLength={200} />
            </Field>
            <Field label="이름">
              <Input name="resourceName" required maxLength={200} />
            </Field>
            <Field label="상위 리소스">
              <Select name="parentResourceId">
                <option value="">없음 (최상위)</option>
                {tree.map(({ resource: r, depth }) => (
                  <option key={r.resourceId} value={r.resourceId}>
                    {"　".repeat(depth)}
                    {r.resourceKey}
                  </option>
                ))}
              </Select>
            </Field>
            <Field label="유형">
              <Select name="resourceType">
                <Options values={RESOURCE_TYPES} labels={LABELS.resourceType} />
              </Select>
            </Field>
            <Field label="민감도">
              <Select name="sensitivity" defaultValue="INTERNAL">
                <Options values={SENSITIVITIES} labels={LABELS.sensitivity} />
              </Select>
            </Field>
            <Field label="경로 (선택)">
              <Input name="resourcePath" maxLength={1000} />
            </Field>
          </div>
        </ActionForm>
      </AddPanel>
      <Card title={`${client.clientName} 리소스`} actions={editing && <Link href={selectedHere} className="text-ink-2 hover:text-ink">닫기</Link>}>
        {isSystem && <p className="mb-3 text-xs text-ink-3">IAM 자체 리소스. 기동 시 코드가 관리합니다</p>}
        {editing && (
          <ActionForm key={editing.resourceId} action={updateResource} submitLabel="저장" className="mb-5 border-b border-line pb-5">
            <input type="hidden" name="clientId" value={client.clientId} />
            <input type="hidden" name="resourceId" value={editing.resourceId} />
            <p className="mb-4 text-ink-3">{editing.resourceKey} 수정. 리소스 키·상위 리소스는 바꿀 수 없습니다</p>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="이름">
                <Input name="resourceName" required maxLength={200} defaultValue={editing.resourceName} />
              </Field>
              <Field label="유형">
                <Select name="resourceType" defaultValue={editing.resourceType}>
                  <Options values={RESOURCE_TYPES} labels={LABELS.resourceType} />
                </Select>
              </Field>
              <Field label="민감도">
                <Select name="sensitivity" defaultValue={editing.sensitivity}>
                  <Options values={SENSITIVITIES} labels={LABELS.sensitivity} />
                </Select>
              </Field>
              <Field label="경로 (선택)">
                <Input name="resourcePath" maxLength={1000} defaultValue={editing.resourcePath ?? ""} />
              </Field>
            </div>
          </ActionForm>
        )}
        <Table headers={["리소스 키", "이름", "유형", "민감도", "상태", ""]} empty={tree.length === 0}>
          {tree.map(({ resource: r, depth }) => (
            <tr key={r.resourceId} className={r.resourceId === resourceId ? "bg-accent-soft" : r.isActive ? undefined : "text-ink-3"}>
              <td style={{ paddingLeft: `${1.25 + depth * 1.25}rem` }}>
                <Link href={`${here}&resourceId=${r.resourceId}`} className="font-mono text-[12px] font-medium text-ink hover:text-accent">
                  {r.resourceKey}
                </Link>
              </td>
              <td>{r.resourceName}</td>
              <td>{label("resourceType", r.resourceType)}</td>
              <td>
                <Badge tone={r.sensitivity === "SECRET" ? "red" : r.sensitivity === "CONFIDENTIAL" ? "amber" : "zinc"}>{label("sensitivity", r.sensitivity)}</Badge>
              </td>
              <td>
                <ActiveBadge active={r.isActive} />
              </td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link href={`${here}&resourceId=${r.resourceId}&editResource=${r.resourceId}`} className={buttonClass.row}>
                    수정
                  </Link>
                  {!isSystem && (
                  <RowAction
                    action={changeResourceActive}
                    label={r.isActive ? "끄기" : "켜기"}
                    tone={r.isActive ? "danger" : "neutral"}
                    hidden={{ clientId: client.clientId, resourceId: r.resourceId, active: String(!r.isActive) }}
                    confirmMessage={r.isActive ? `'${r.resourceKey}' 리소스를 끌까요? 이 리소스의 권한이 판정에서 빠집니다` : undefined}
                  />
                  )}
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
      {selected && <ResourcePermissions resource={selected} here={`${here}&resourceId=${selected.resourceId}`} editId={param(params, "editPermission")} isSystem={isSystem} />}
    </>
  );
}

/** [isSystem] 이면 관리 콘솔 자신의 권한이라 끄기 버튼을 숨긴다 (끄면 관리 API 가 막혀 되돌릴 수 없다) */
async function ResourcePermissions({ resource, here, editId, isSystem }: { resource: Resource; here: string; editId?: number; isSystem: boolean }) {
  const permissions = await query<Permission[]>(`/api/v1/permissions?resourceId=${resource.resourceId}`, here);
  const editing = permissions.find((p) => p.permissionId === editId);

  return (
    <>
      <AddPanel label="권한 추가">
        <ActionForm action={createPermission} submitLabel="권한 추가" resetOnSuccess>
          <input type="hidden" name="clientId" value={resource.clientId} />
          <input type="hidden" name="resourceId" value={resource.resourceId} />
          <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
            <Field label="권한 코드">
              <Input name="permissionCode" required maxLength={100} />
            </Field>
            <Field label="이름">
              <Input name="permissionName" required maxLength={200} />
            </Field>
            <Field label="동작">
              <Select name="action">
                <Options values={ACTIONS} labels={LABELS.action} />
              </Select>
            </Field>
            <Field label="효과" hint="거부가 허용보다 우선합니다">
              <Select name="effect">
                <Options values={EFFECTS} labels={LABELS.effect} />
              </Select>
            </Field>
          </div>
        </ActionForm>
      </AddPanel>
      <Card title={`${resource.resourceKey} 권한`} actions={editing && <Link href={here} className="text-ink-2 hover:text-ink">닫기</Link>}>
        {editing && (
          <ActionForm key={editing.permissionId} action={updatePermission} submitLabel="저장" className="mb-5 border-b border-line pb-5">
            <input type="hidden" name="clientId" value={resource.clientId} />
            <input type="hidden" name="resourceId" value={resource.resourceId} />
            <input type="hidden" name="permissionId" value={editing.permissionId} />
            <p className="mb-4 text-ink-3">{editing.permissionCode} 이름 바꾸기. 동작·효과는 바꿀 수 없습니다</p>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
              <Field label="이름">
                <Input name="permissionName" required maxLength={200} defaultValue={editing.permissionName} />
              </Field>
            </div>
          </ActionForm>
        )}
        <Table headers={["권한 코드", "이름", "동작", "효과", "상태", ""]} empty={permissions.length === 0}>
          {permissions.map((p) => (
            <tr key={p.permissionId} className={p.isActive ? undefined : "text-ink-3"}>
              <td>
                <Mono>{p.permissionCode}</Mono>
              </td>
              <td>{p.permissionName}</td>
              <td>{label("action", p.action)}</td>
              <td>
                <Badge tone={p.effect === "DENY" ? "red" : "green"}>{label("effect", p.effect)}</Badge>
              </td>
              <td>
                <ActiveBadge active={p.isActive} />
              </td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link href={`${here}&editPermission=${p.permissionId}`} className={buttonClass.row}>
                    이름 바꾸기
                  </Link>
                  {!isSystem && (
                  <RowAction
                    action={changePermissionActive}
                    label={p.isActive ? "끄기" : "켜기"}
                    tone={p.isActive ? "danger" : "neutral"}
                    hidden={{ clientId: resource.clientId, resourceId: resource.resourceId, permissionId: p.permissionId, active: String(!p.isActive) }}
                    confirmMessage={p.isActive ? `'${p.permissionCode}' 권한을 끌까요? 이 권한이 판정에서 빠집니다` : undefined}
                  />
                  )}
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </>
  );
}
