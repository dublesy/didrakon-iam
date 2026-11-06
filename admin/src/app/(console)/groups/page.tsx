import Link from "next/link";
import { Suspense } from "react";
import { ActionForm } from "@/components/action-form";
import { AddPanel, Badge, Card, Field, Input, Loading, Mono, Options, PageHeader, Select, Table, Textarea } from "@/components/ui";
import { LABELS, label } from "@/lib/labels";
import { query } from "@/lib/queries";
import { GROUP_TYPES, type Group } from "@/lib/types";
import { createGroup } from "./actions";

export default function GroupsPage() {
  return (
    <>
      <PageHeader title="그룹" description="조직과 별개로 묶는 사용자 그룹. 그룹 역할 규칙은 상세에서 관리합니다." />
      <div className="space-y-6">
        <AddPanel label="그룹 추가">
          <ActionForm action={createGroup} submitLabel="만들기" resetOnSuccess>
            <div className="grid grid-cols-2 gap-3 md:grid-cols-3">
              <Field label="코드">
                <Input name="groupCode" required maxLength={100} />
              </Field>
              <Field label="이름">
                <Input name="groupName" required maxLength={200} />
              </Field>
              <Field label="유형">
                <Select name="groupType">
                  <Options values={GROUP_TYPES} labels={LABELS.groupType} />
                </Select>
              </Field>
            </div>
            <div className="mt-3">
              <Field label="규칙식" hint="규칙 그룹에만 씁니다">
                <Textarea name="ruleExpression" rows={2} />
              </Field>
            </div>
          </ActionForm>
        </AddPanel>
        <Suspense fallback={<Loading />}>
          <GroupList />
        </Suspense>
      </div>
    </>
  );
}

async function GroupList() {
  const groups = await query<Group[]>("/api/v1/groups", "/groups");

  return (
    <Card>
      <Table headers={["이름", "코드", "유형"]} empty={groups.length === 0}>
        {groups.map((g) => (
          <tr key={g.groupId} className={g.isActive ? undefined : "text-ink-3"}>
            <td>
              <span className="inline-flex items-center gap-2">
                <Link href={`/groups/${g.groupId}`} className={`font-medium hover:text-accent ${g.isActive ? "text-ink" : "text-ink-3"}`}>
                  {g.groupName}
                </Link>
                {!g.isActive && <Badge>꺼짐</Badge>}
              </span>
            </td>
            <td>
              <Mono>{g.groupCode}</Mono>
            </td>
            <td>{label("groupType", g.groupType)}</td>
          </tr>
        ))}
      </Table>
    </Card>
  );
}
