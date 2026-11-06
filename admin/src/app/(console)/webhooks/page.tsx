import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Checkbox, Field, Input, Loading, Mono, PageHeader, Table, buttonClass } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query } from "@/lib/queries";
import { WEBHOOK_DELIVERY_STATUSES, WEBHOOK_EVENT_TYPES, type Webhook, type WebhookDelivery } from "@/lib/types";
import { changeWebhookActive, createWebhook, redeliverWebhook, rotateWebhookSecret, sendWebhookTest, updateWebhook } from "./actions";

const STATUS_TONES: Record<string, "zinc" | "green" | "amber" | "red"> = { PENDING: "zinc", SUCCEEDED: "green", FAILED: "amber", DEAD: "red" };

export default function WebhooksPage({ searchParams }: PageProps<"/webhooks">) {
  return (
    <>
      <PageHeader
        title="웹훅"
        description="사용자 상태·소속·조직 이동·역할 할당·접근 요청·인증 수단·접근 재검토·설정 변경을 연동 시스템에 알립니다. 변경이 저장된 뒤 구독마다 생긴 순서대로 보내며, 내부망 주소로는 보내지 않습니다. 받는 쪽이 실패하면 30초·2분·10분·1시간·6시간 간격으로 다시 보내고 여섯 번째 실패에서 멈춥니다."
      />
      <Suspense fallback={<Loading />}>
        <WebhookList searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function WebhookList({ searchParams }: { searchParams: PageProps<"/webhooks">["searchParams"] }) {
  const params = await searchParams;
  const webhooks = await query<Webhook[]>("/api/v1/webhooks", "/webhooks");
  const editing = webhooks.find((w) => String(w.webhookId) === params.edit);
  const selected = webhooks.find((w) => String(w.webhookId) === params.id);

  return (
    <div className="space-y-6">
      {editing ? (
        <Card title={`${editing.name} 수정`} actions={<Link href="/webhooks" className="text-ink-2 hover:text-ink">닫기</Link>}>
          <ActionForm key={editing.webhookId} action={updateWebhook} submitLabel="저장">
            <input type="hidden" name="webhookId" value={editing.webhookId} />
            <WebhookFields webhook={editing} />
          </ActionForm>
        </Card>
      ) : (
        <AddPanel label="웹훅 추가">
          <ActionForm action={createWebhook} submitLabel="추가" resetOnSuccess>
            <WebhookFields />
          </ActionForm>
        </AddPanel>
      )}

      <Card title="구독">
        <Table headers={["이름", "주소", "이벤트", "상태", "최근 7일 전달", ""]} empty={webhooks.length === 0} emptyText="등록한 웹훅이 없습니다">
          {webhooks.map((w) => (
            <tr key={w.webhookId} className={w.isActive ? undefined : "text-ink-3"}>
              <td className="font-medium">{w.name}</td>
              <td className="max-w-[28ch] truncate" title={w.url}>
                <Mono>{w.url}</Mono>
              </td>
              <td className="text-ink-2">{w.eventTypes.map((t) => label("webhookEvent", t)).join(", ")}</td>
              <td>{w.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}</td>
              <td>
                <DeliveryCounts counts={w.recentCounts} />
              </td>
              <td>
                <span className="flex justify-end gap-2">
                  <Link href={`/webhooks?id=${w.webhookId}`} className={buttonClass.row}>
                    전달 기록
                  </Link>
                  <Link href={`/webhooks?edit=${w.webhookId}`} className={buttonClass.row}>
                    수정
                  </Link>
                  <RowAction
                    action={changeWebhookActive}
                    label={w.isActive ? "끄기" : "켜기"}
                    tone={w.isActive ? "danger" : "neutral"}
                    hidden={{ webhookId: w.webhookId, active: String(!w.isActive) }}
                    confirmMessage={w.isActive ? `'${w.name}' 웹훅을 끌까요? 켤 때까지 새 변경을 보내지 않고, 남은 전달도 멈춥니다` : undefined}
                  />
                </span>
              </td>
            </tr>
          ))}
        </Table>
      </Card>

      {selected && <Deliveries webhook={selected} />}

      <Card title="검증 방법">
        <div className="space-y-3 text-ink-2">
          <p>
            본문은 JSON <Mono>{`{"id", "type", "occurredAt", "data"}`}</Mono> 입니다. <Mono>data</Mono> 에는 ID 와 상태 코드만 들어 있으니 자세한 내용은 IAM API 로 조회하세요.
          </p>
          <p>
            헤더 <Mono>X-Didrakon-Signature</Mono> 는 <Mono>sha256=</Mono> 뒤에 HMAC-SHA256(서명 비밀값, <Mono>X-Didrakon-Timestamp</Mono> + <Mono>.</Mono> + 받은 본문 그대로)을 16진수로 붙인 값입니다. 같은 값을 계산해 비교하고, 타임스탬프(초)가 5분보다 오래됐으면 거부하세요.
          </p>
          <p>
            같은 전달이 두 번 올 수 있습니다. <Mono>X-Didrakon-Delivery</Mono>(전달 ID)나 본문의 <Mono>id</Mono>(이벤트 ID)로 이미 처리했는지 확인하세요. 2xx 로 답하면 성공으로 봅니다. 앞 전달이 성공하거나 멈출 때까지 다음 전달은 기다립니다.
          </p>
        </div>
      </Card>
    </div>
  );
}

async function Deliveries({ webhook }: { webhook: Webhook }) {
  const deliveries = await query<WebhookDelivery[]>(`/api/v1/webhooks/${webhook.webhookId}/deliveries`, `/webhooks?id=${webhook.webhookId}`);
  return (
    <Card title={`${webhook.name} 전달 기록`} actions={<Link href="/webhooks" className="text-ink-2 hover:text-ink">닫기</Link>}>
      <div className="mb-4 flex flex-wrap items-start gap-x-6">
        <ActionForm action={sendWebhookTest} submitLabel="시험 보내기" variant="subtle">
          <input type="hidden" name="webhookId" value={webhook.webhookId} />
        </ActionForm>
        <ActionForm
          action={rotateWebhookSecret}
          submitLabel="비밀값 바꾸기"
          variant="subtle"
          confirmMessage={`'${webhook.name}' 의 서명 비밀값을 바꿀까요? 이전 값은 바로 쓸 수 없게 되므로 받는 시스템에도 새 값을 넣어야 합니다`}
        >
          <input type="hidden" name="webhookId" value={webhook.webhookId} />
        </ActionForm>
      </div>
      <Table
        headers={["만든 시각", "이벤트", "상태", "시도", "응답", "다음 시도", "전달 ID", ""]}
        empty={deliveries.length === 0}
        emptyText="아직 전달이 없습니다"
      >
        {deliveries.map((d) => (
          <tr key={d.deliveryId}>
            <td className="tabular-nums">{formatTime(d.createdAt)}</td>
            <td>{label("webhookEvent", d.eventType)}</td>
            <td>
              <Badge tone={STATUS_TONES[d.status] ?? "zinc"}>{label("deliveryStatus", d.status)}</Badge>
            </td>
            <td className="tabular-nums">{d.attempts}</td>
            <td title={d.lastError ?? undefined}>
              <Mono>{d.lastStatusCode ?? d.lastError ?? "—"}</Mono>
            </td>
            <td className="tabular-nums">{d.status === "PENDING" || d.status === "FAILED" ? formatTime(d.nextAttemptAt) : "—"}</td>
            <td>
              <Mono>{d.deliveryId}</Mono>
            </td>
            <td>
              <span className="flex justify-end">
                <RowAction action={redeliverWebhook} label="다시 보내기" tone="neutral" hidden={{ deliveryId: d.deliveryId, webhookId: webhook.webhookId }} />
              </span>
            </td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}

function DeliveryCounts({ counts }: { counts: Record<string, number> }) {
  const shown = WEBHOOK_DELIVERY_STATUSES.filter((s) => (counts[s] ?? 0) > 0);
  if (shown.length === 0) return <span className="text-ink-3">—</span>;
  return (
    <span className="flex flex-wrap gap-1">
      {shown.map((s) => (
        <Badge key={s} tone={STATUS_TONES[s]}>
          {label("deliveryStatus", s)} {counts[s]}
        </Badge>
      ))}
    </span>
  );
}

function WebhookFields({ webhook }: { webhook?: Webhook }) {
  const all = webhook?.eventTypes.includes("*") ?? false;
  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Field label="이름">
          <Input name="name" required maxLength={200} defaultValue={webhook?.name} />
        </Field>
        <Field label="받는 주소" hint="http(s) 절대 주소. 운영에서는 https 를 쓰세요">
          <Input name="url" type="url" required maxLength={500} defaultValue={webhook?.url} placeholder="https://erp.example.com/hooks/iam" />
        </Field>
      </div>
      <fieldset>
        <legend className="mb-1.5 text-[13px] font-medium text-ink-2">받을 이벤트</legend>
        <div className="flex flex-wrap gap-x-5">
          <Checkbox name="eventTypes" value="*" label={label("webhookEvent", "*")} defaultChecked={all} />
          {WEBHOOK_EVENT_TYPES.map((t) => (
            <Checkbox key={t} name="eventTypes" value={t} label={label("webhookEvent", t)} defaultChecked={!all && (webhook?.eventTypes.includes(t) ?? false)} />
          ))}
        </div>
        <p className="mt-1 text-xs text-ink-3">전체를 고르면 나중에 생기는 유형도 받습니다</p>
      </fieldset>
    </div>
  );
}
