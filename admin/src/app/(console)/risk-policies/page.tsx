import Link from "next/link";
import { Suspense } from "react";
import { ActionForm, RowAction } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Options, PageHeader, Select, Table, buttonClass } from "@/components/ui";
import { label, LABELS } from "@/lib/labels";
import { query } from "@/lib/queries";
import { RISK_ACTIONS, RISK_TYPES, type RiskPolicy } from "@/lib/types";
import { changeRiskPolicyActive, createRiskPolicy, updateRiskPolicy } from "./actions";
import { ConditionFields } from "./condition-fields";

const ACTION_TONES: Record<string, "zinc" | "amber" | "red" | "blue"> = { ALLOW: "zinc", CHALLENGE: "blue", APPROVAL: "amber", DENY: "red" };

export default function RiskPoliciesPage({ searchParams }: PageProps<"/risk-policies">) {
  return (
    <>
      <PageHeader
        title="위험 정책"
        description="같은 상황에서 켜진 정책 중 신호가 잡힌 것의 점수를 더합니다. 합이 80 이상이면 정책과 관계없이 차단합니다. 로그인은 차단이면 막고, 추가 인증·승인 필요면 2단계 인증을 요구합니다(등록하지 않은 사용자는 막음). 권한 판정은 점수를 ABAC 정책(riskScore)에 넘깁니다."
      />
      <Suspense fallback={<Loading />}>
        <PolicyList searchParams={searchParams} />
      </Suspense>
    </>
  );
}

async function PolicyList({ searchParams }: { searchParams: PageProps<"/risk-policies">["searchParams"] }) {
  const params = await searchParams;
  const policies = await query<RiskPolicy[]>("/api/v1/risk-policies", "/risk-policies");
  const editing = policies.find((p) => String(p.riskPolicyId) === params.edit);

  return (
    <div className="space-y-6">
      {editing ? (
        <Card title={`${editing.policyName} 수정`} actions={<Link href="/risk-policies" className="text-ink-2 hover:text-ink">닫기</Link>}>
          <p className="mb-4 text-ink-3">평가 상황({label("riskType", editing.riskType)})은 바꿀 수 없습니다. 바꾸려면 새 정책을 추가하세요</p>
          <ActionForm key={editing.riskPolicyId} action={updateRiskPolicy} submitLabel="저장">
            <input type="hidden" name="riskPolicyId" value={editing.riskPolicyId} />
            <PolicyFields policy={editing} />
          </ActionForm>
        </Card>
      ) : (
        <AddPanel label="위험 정책 추가">
          <ActionForm action={createRiskPolicy} submitLabel="추가" resetOnSuccess>
            <PolicyFields />
          </ActionForm>
        </AddPanel>
      )}

      {RISK_TYPES.map((type) => {
        const rows = policies.filter((p) => p.riskType === type);
        return (
          <Card key={type} title={label("riskType", type)}>
            <Table headers={["이름", "신호", "조건", "점수", "조치", "상태", ""]} empty={rows.length === 0} emptyText="정책이 없습니다">
              {rows.map((p) => (
                <tr key={p.riskPolicyId} className={p.isActive ? undefined : "text-ink-3"}>
                  <td className="font-medium">{p.policyName}</td>
                  <td>{label("riskSignal", parse(p.conditionExpression).signal)}</td>
                  <td className="text-ink-2">{describe(parse(p.conditionExpression))}</td>
                  <td className="tabular-nums">{p.riskScore}</td>
                  <td>
                    <Badge tone={ACTION_TONES[p.action] ?? "zinc"}>{label("riskAction", p.action)}</Badge>
                  </td>
                  <td>{p.isActive ? <Badge tone="green">켜짐</Badge> : <Badge>꺼짐</Badge>}</td>
                  <td>
                    <span className="flex justify-end gap-2">
                      <Link
                        href={`/risk-policies?edit=${p.riskPolicyId}`}
                        className={buttonClass.row}
                      >
                        수정
                      </Link>
                      <RowAction
                        action={changeRiskPolicyActive}
                        label={p.isActive ? "끄기" : "켜기"}
                        tone={p.isActive ? "danger" : "neutral"}
                        hidden={{ riskPolicyId: p.riskPolicyId, active: String(!p.isActive) }}
                        confirmMessage={p.isActive ? `'${p.policyName}' 정책을 끌까요? 바로 평가에서 빠집니다` : undefined}
                      />
                    </span>
                  </td>
                </tr>
              ))}
            </Table>
          </Card>
        );
      })}
    </div>
  );
}

function PolicyFields({ policy }: { policy?: RiskPolicy }) {
  return (
    <div className="grid grid-cols-2 gap-3 md:grid-cols-4">
      {!policy && (
        <Field label="평가 상황">
          <Select name="riskType">
            <Options values={RISK_TYPES} labels={LABELS.riskType} />
          </Select>
        </Field>
      )}
      <Field label="이름">
        <Input name="policyName" required maxLength={200} defaultValue={policy?.policyName} />
      </Field>
      <Field label="점수" hint="0~100. 합이 80 이상이면 차단">
        <Input name="riskScore" type="number" min={0} max={100} required defaultValue={policy?.riskScore ?? 20} />
      </Field>
      <Field label="조치">
        <Select name="action" defaultValue={policy?.action ?? "CHALLENGE"}>
          <Options values={RISK_ACTIONS} labels={LABELS.riskAction} />
        </Select>
      </Field>
      <ConditionFields initial={policy ? parse(policy.conditionExpression) : undefined} />
    </div>
  );
}

type Condition = { signal?: string; from?: string; to?: string; threshold?: number; windowSeconds?: number; allowedCountries?: string[] };

function parse(json: string): Condition {
  try {
    return JSON.parse(json) as Condition;
  } catch {
    return {};
  }
}

/** 조건을 사람이 읽는 문장으로. 비운 값은 엔진 기본값으로 적는다 */
function describe(c: Condition): string {
  switch (c.signal) {
    case "UNUSUAL_TIME":
      return `${c.from ?? "07:00"}~${c.to ?? "22:00"} 밖`;
    case "FAILED_LOGIN_BURST":
      return `연속 ${c.threshold ?? 3}회 이상 실패`;
    case "MASS_ACCESS":
      return `${c.windowSeconds ?? 60}초에 ${c.threshold ?? 100}회 이상`;
    case "FOREIGN_IP":
      return `허용 국가 ${(c.allowedCountries ?? ["KR"]).join(", ")} 밖`;
    case "NEW_DEVICE":
      return "처음 쓰는 브라우저";
    default:
      return "—";
  }
}
