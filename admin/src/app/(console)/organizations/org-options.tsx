import type { Organization } from "@/lib/types";

/** 조직 select 옵션. 레벨만큼 들여쓴다 */
export function OrgOptions({ orgs }: { orgs: Organization[] }) {
  return orgs.map((o) => (
    <option key={o.orgId} value={o.orgId}>
      {"　".repeat(Math.max(0, o.orgLevel - 1))}
      {o.orgName}
    </option>
  ));
}
