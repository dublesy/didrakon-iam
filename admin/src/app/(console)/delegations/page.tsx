import { Suspense } from "react";
import { RowAction } from "@/components/action-form";
import { Badge, Card, Loading, Mono, PageHeader, Table } from "@/components/ui";
import { label } from "@/lib/labels";
import { formatTime, query } from "@/lib/queries";
import type { Delegation } from "@/lib/types";
import { revokeDelegation } from "./actions";

const STATUS_TONES: Record<string, "zinc" | "green" | "amber"> = { PENDING: "amber", ACTIVE: "green", EXPIRED: "zinc", REVOKED: "zinc" };

export default function DelegationsPage() {
  return (
    <>
      <PageHeader
        title="위임"
        description="사람이 자기 역할을 기간을 정해 다른 사람에게 맡긴 기록입니다. 위임은 본인이 내 권한 요청 화면에서 하고, 여기서는 진행 중인 위임을 회수할 수 있습니다. 위임자가 역할을 잃으면 위임도 자동으로 끝납니다."
      />
      <Suspense fallback={<Loading />}>
        <DelegationList />
      </Suspense>
    </>
  );
}

async function DelegationList() {
  const delegations = await query<Delegation[]>("/api/v1/delegations", "/delegations");

  return (
    <Card>
      <p className="mb-4 text-ink-2">진행 중·시작 전 위임 전부와 최근 200건입니다. 회수하면 대리인이 받은 역할이 바로 사라집니다.</p>
      <Table headers={["위임자", "대리인", "역할", "범위", "기간", "사유", "상태", ""]} empty={delegations.length === 0} emptyText="위임 기록이 없습니다">
        {delegations.map((d) => {
          const open = d.status === "PENDING" || d.status === "ACTIVE";
          return (
            <tr key={d.delegationId} className={`[&>td]:py-2.5 [&>td]:align-top ${open ? "" : "text-ink-3"}`}>
              <td>{d.delegatorName ?? d.delegatorId}</td>
              <td>{d.delegateName ?? d.delegateId}</td>
              <td>{d.roleName ?? d.roleId}</td>
              <td>
                <Mono>{d.scopeCode ?? d.scopeId}</Mono>
              </td>
              <td className="font-mono text-xs whitespace-nowrap tabular-nums">
                {formatTime(d.startTime)} ~ {formatTime(d.endTime)}
              </td>
              <td className="max-w-[32ch]">{d.reason}</td>
              <td>
                <Badge tone={STATUS_TONES[d.status] ?? "zinc"}>{label("delegationStatus", d.status)}</Badge>
              </td>
              <td>
                {open && (
                  <span className="flex justify-end">
                    <RowAction
                      action={revokeDelegation}
                      label="회수"
                      hidden={{ delegationId: d.delegationId }}
                      confirmMessage={`${d.delegatorName ?? d.delegatorId} → ${d.delegateName ?? d.delegateId} 의 '${d.roleName ?? d.roleId}' 위임을 회수할까요?`}
                    />
                  </span>
                )}
              </td>
            </tr>
          );
        })}
      </Table>
    </Card>
  );
}
