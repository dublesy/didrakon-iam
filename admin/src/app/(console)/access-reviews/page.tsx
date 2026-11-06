import Link from "next/link";
import { Suspense, type ReactNode } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, Options, PageHeader, Select, SourceStamp, Table, buttonClass } from "@/components/ui";
import { LABELS, SOURCE_LABELS, label } from "@/lib/labels";
import { formatTime, query } from "@/lib/queries";
import {
  REVIEW_DECISIONS,
  REVIEW_DEFAULT_SOURCES,
  REVIEW_SCOPE_TYPES,
  REVIEW_SOURCES,
  type AccessReviewCampaign,
  type AccessReviewDetail,
  type Organization,
  type Role,
} from "@/lib/types";
import { OrgOptions } from "../organizations/org-options";
import { closeReview, createReview, decideReviewItem } from "./actions";

const DECISION_TONES: Record<string, "zinc" | "green" | "red"> = { PENDING: "zinc", KEEP: "green", REVOKE: "red" };

type SearchParams = Promise<Record<string, string | string[] | undefined>>;

export default function AccessReviewsPage({ searchParams }: { searchParams: SearchParams }) {
  return (
    <>
      <PageHeader
        title="접근 재검토"
        description="역할 할당을 주기적으로 담당자가 확인해 유지·회수하고, 결과를 증적으로 남깁니다. 검토자는 대상자 주 소속 조직의 관리자이고, 관리자가 없으면 여기서 정합니다. 기한이 지나면 남은 항목에 정한 처리를 하고 닫습니다. 상위 관리자 이관을 정하면 먼저 남은 항목을 상위 조직 관리자에게 넘기고 그만큼 더 기다립니다"
      />
      <Suspense fallback={<Loading />}>
        <Reviews searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function Reviews({ searchParams }: { searchParams: SearchParams }) {
  const params = await searchParams;
  const here = "/access-reviews";
  const [campaigns, orgs, roles] = await Promise.all([
    query<AccessReviewCampaign[]>("/api/v1/access-reviews", here),
    query<Organization[]>("/api/v1/organizations", here),
    query<Role[]>("/api/v1/roles", here),
  ]);
  const orgName = new Map(orgs.map((o) => [o.orgId, o.orgName]));
  const roleName = new Map(roles.map((r) => [r.roleId, r.roleName]));
  const scopeText = (c: AccessReviewCampaign) =>
    c.scopeType === "ORGANIZATION"
      ? `${orgName.get(c.scopeOrgId ?? -1) ?? c.scopeOrgId}${c.includeDescendants ? " (하위 포함)" : ""}`
      : c.scopeType === "ROLE"
        ? `${roleName.get(c.scopeRoleId ?? -1) ?? c.scopeRoleId}`
        : label("reviewScope", c.scopeType);
  const selected = campaigns.find((c) => String(c.campaignId) === params.id);
  const decision = typeof params.decision === "string" && (REVIEW_DECISIONS as readonly string[]).includes(params.decision) ? params.decision : undefined;

  return (
    <div className="space-y-6">
      {selected ? (
        <Detail campaign={selected} scope={scopeText(selected)} decision={decision} />
      ) : (
        <AddPanel label="재검토 시작">
          <ActionForm action={createReview} submitLabel="시작" resetOnSuccess>
            <div className="grid gap-4 sm:grid-cols-2">
              <Field label="이름">
                <Input name="name" required maxLength={200} placeholder="2026 하반기 정기 접근 권한 점검" />
              </Field>
              <Field label="검토 기한 (한국 시각)">
                <Input name="dueAt" type="datetime-local" required />
              </Field>
              <Field label="대상" hint="조직은 그 조직을 주 소속으로 둔 사람의 할당이 대상입니다">
                <Select name="scopeType" defaultValue="ORGANIZATION">
                  <Options values={REVIEW_SCOPE_TYPES} labels={LABELS.reviewScope} />
                </Select>
              </Field>
              <Field label="기한이 지나면">
                <Select name="onOverdue" defaultValue="KEEP">
                  <option value="KEEP">유지 (재검토 표시는 남김)</option>
                  <option value="REVOKE">회수</option>
                </Select>
              </Field>
              <Field label="상위 관리자 이관 (일)" hint="비우면 기한에 바로 처리합니다. 넣으면 기한이 지났을 때 남은 항목을 상위 조직 관리자에게 넘기고 그만큼 더 기다립니다">
                <Input name="escalationDays" type="number" min={1} max={30} placeholder="예: 7" />
              </Field>
              <Field label="대상 조직" hint="대상이 조직일 때만 씁니다">
                <Select name="scopeOrgId">
                  <OrgOptions orgs={orgs.filter((o) => o.isActive)} />
                </Select>
              </Field>
              <Field label="대상 역할" hint="대상이 역할일 때만 씁니다">
                <Select name="scopeRoleId">
                  {roles
                    .filter((r) => r.isActive)
                    .map((r) => (
                      <option key={r.roleId} value={r.roleId}>
                        {r.roleName} ({r.roleCode})
                      </option>
                    ))}
                </Select>
              </Field>
            </div>
            <fieldset className="mt-4">
              <legend className="text-[13px] font-medium text-ink-2">대상 할당 출처</legend>
              <div className="flex flex-wrap gap-x-5">
                {REVIEW_SOURCES.map((s) => (
                  <Checkbox key={s} name="sources" value={s} label={SOURCE_LABELS[s] ?? s} defaultChecked={REVIEW_DEFAULT_SOURCES.includes(s)} />
                ))}
              </div>
              <p className="text-xs text-ink-3">
                조직·그룹 규칙으로 생긴 할당은 개별로 회수할 수 없어 역할 규칙을 바꿔 검토합니다. 전적 등으로 재검토 표시가 붙은 할당은 출처·특권 조건과 관계없이 들어갑니다
              </p>
            </fieldset>
            <div className="mt-2 flex flex-wrap gap-x-5">
              <Checkbox name="includeDescendants" label="하위 조직 포함" defaultChecked />
              <Checkbox name="privilegedOnly" label="특권 역할만" />
            </div>
          </ActionForm>
        </AddPanel>
      )}

      <Card title="캠페인">
        <Table headers={["이름", "대상", "기한", "진행", "상태", ""]} empty={campaigns.length === 0} emptyText="아직 시작한 재검토가 없습니다">
          {campaigns.map((c) => (
            <tr key={c.campaignId} className={c.status === "CLOSED" ? "text-ink-3" : undefined}>
              <td className="font-medium">{c.name}</td>
              <td className="text-ink-2">
                {label("reviewScope", c.scopeType)} · {scopeText(c)}
                {c.privilegedOnly && " · 특권만"}
              </td>
              <td className="tabular-nums whitespace-nowrap">
                {formatTime(c.dueAt)}
                {c.escalatedAt && <div className="text-xs text-ink-3">이관 뒤 {formatTime(c.finalDueAt)}</div>}
              </td>
              <td>
                <Progress campaign={c} />
              </td>
              <td>{c.status === "OPEN" ? <Badge tone="blue">{label("reviewStatus", c.status)}</Badge> : <Badge>{label("reviewStatus", c.status)}</Badge>}</td>
              <td>
                <span className="flex justify-end">
                  <Link href={`/access-reviews?id=${c.campaignId}`} className={buttonClass.row}>
                    항목 보기
                  </Link>
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>
    </div>
  );
}

/** 결정한 비율 막대와 유지·회수·미결정 수 */
function Progress({ campaign: c }: { campaign: AccessReviewCampaign }) {
  const done = c.total - c.pending;
  const percent = c.total === 0 ? 0 : Math.round((done / c.total) * 100);
  return (
    <div className="flex min-w-48 items-center gap-3">
      <div className="h-1.5 w-24 overflow-hidden rounded-full bg-panel" role="progressbar" aria-valuenow={percent} aria-valuemin={0} aria-valuemax={100} aria-label="결정 비율">
        <div className="h-full bg-accent" style={{ width: `${percent}%` }} />
      </div>
      <span className="text-xs whitespace-nowrap text-ink-2 tabular-nums">
        {done}/{c.total} · 유지 {c.kept} · 회수 {c.revoked}
      </span>
    </div>
  );
}

async function Detail({ campaign: c, scope, decision }: { campaign: AccessReviewCampaign; scope: string; decision?: string }) {
  const here = `/access-reviews?id=${c.campaignId}`;
  const { items } = await query<AccessReviewDetail>(`/api/v1/access-reviews/${c.campaignId}${decision ? `?decision=${decision}` : ""}`, here);
  const open = c.status === "OPEN";
  const filterHref = (d?: string) => `/access-reviews?id=${c.campaignId}${d ? `&decision=${d}` : ""}`;

  return (
    <Card title={c.name} actions={<Link href="/access-reviews" className="text-ink-2 hover:text-ink">닫기</Link>}>
      <dl className="mb-4 grid gap-x-6 gap-y-2 text-[13px] sm:grid-cols-4">
        <Meta label="대상">
          {label("reviewScope", c.scopeType)} · {scope}
          {c.privilegedOnly && " · 특권만"}
        </Meta>
        <Meta label="출처">
          <span className="flex flex-wrap gap-1">
            {c.sources.map((s) => (
              <SourceStamp key={s} source={s} />
            ))}
          </span>
        </Meta>
        <Meta label="기한">
          {formatTime(c.dueAt)} ·{" "}
          {c.escalationDays ? (
            <>
              지나면 상위 관리자에게 넘기고 {c.escalationDays}일 뒤({formatTime(c.finalDueAt)}) {label("reviewDecision", c.onOverdue)}
              {c.escalatedAt && (
                <span className="ml-2">
                  <Badge tone="amber">이관함 {formatTime(c.escalatedAt)}</Badge>
                </span>
              )}
            </>
          ) : (
            <>지나면 {label("reviewDecision", c.onOverdue)}</>
          )}
        </Meta>
        <Meta label="진행">
          <Progress campaign={c} />
        </Meta>
      </dl>

      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <nav aria-label="결정 거르기" className="flex flex-wrap gap-1">
          {[undefined, ...REVIEW_DECISIONS].map((d) => (
            <Link
              key={d ?? "all"}
              href={filterHref(d)}
              aria-current={d === decision ? "page" : undefined}
              className={`inline-flex h-7 items-center rounded-md px-2 text-xs font-medium transition-colors ${
                d === decision ? "bg-accent-soft text-accent" : "text-ink-2 hover:bg-panel hover:text-ink"
              }`}
            >
              {d ? label("reviewDecision", d) : "전체"}
            </Link>
          ))}
        </nav>
        <div className="flex flex-wrap items-start gap-3">
          <a href={`/access-reviews/${c.campaignId}/export`} className={buttonClass.secondary}>
            증적 CSV 내려받기
          </a>
          {open && (
            <ActionForm
              action={closeReview}
              submitLabel="지금 마감"
              variant="danger"
              className="[&>div]:mt-0"
              confirmMessage={`'${c.name}' 을(를) 마감할까요? 남은 ${c.pending}건은 '${label("reviewDecision", c.onOverdue)}' 로 처리되고 되돌릴 수 없습니다`}
            >
              <input type="hidden" name="campaignId" value={c.campaignId} />
            </ActionForm>
          )}
        </div>
      </div>

      <Table
        headers={["대상자", "소속", "역할", "범위", "출처", "검토자", "결정", ""]}
        empty={items.length === 0}
        emptyText={decision ? "해당하는 항목이 없습니다" : "항목이 없습니다"}
      >
        {items.map((i) => (
          <tr key={i.itemId} className="[&>td]:py-2">
            <td>
              <div className="font-medium">{i.subjectName}</div>
              {i.empNo && <Mono>{i.empNo}</Mono>}
            </td>
            <td className="text-ink-2">{i.orgName ?? "—"}</td>
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
            <td className="text-ink-2">
              {i.reviewerName ?? "관리자"}
              {i.escalatedAt && (
                <div className="mt-1 text-xs text-ink-3">
                  <Badge tone="amber">이관</Badge> {i.escalatedFromName ?? "관리자"}에게서
                </div>
              )}
            </td>
            <td>
              <Badge tone={DECISION_TONES[i.decision] ?? "zinc"}>{label("reviewDecision", i.decision)}</Badge>
              {i.decision !== "PENDING" && (
                <div className="mt-1 text-xs text-ink-3">
                  {i.decidedByName ?? (i.decidedBy ? `#${i.decidedBy}` : "자동")} · <span className="tabular-nums">{formatTime(i.decidedAt)}</span>
                  {i.comment && <div className="text-ink-2">{i.comment}</div>}
                </div>
              )}
            </td>
            <td>
              {open && i.decision === "PENDING" && (
                <span className="flex justify-end gap-2">
                  <RowAction
                    action={decideReviewItem}
                    label="유지"
                    tone="neutral"
                    hidden={{ itemId: i.itemId, campaignId: c.campaignId, decision: "KEEP" }}
                  />
                  <RowAction
                    action={decideReviewItem}
                    label="회수"
                    hidden={{ itemId: i.itemId, campaignId: c.campaignId, decision: "REVOKE" }}
                    confirmMessage={`${i.subjectName} 의 '${i.roleName}' 역할을 지금 회수할까요?`}
                  />
                </span>
              )}
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function Meta({ label: name, children }: { label: string; children: ReactNode }) {
  return (
    <div className="min-w-0">
      <dt className="text-xs text-ink-3">{name}</dt>
      <dd className="mt-0.5 text-ink">{children}</dd>
    </div>
  );
}
