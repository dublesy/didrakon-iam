/** IAM 관리 API 리소스 키 (백엔드 ApiResources 와 같은 값) */
export const RESOURCE = {
  USER: "iam.identity.user",
  ORGANIZATION: "iam.identity.organization",
  MEMBERSHIP: "iam.identity.membership",
  GROUP: "iam.identity.group",
  RESOURCE: "iam.authz.resource",
  ROLE: "iam.authz.role",
  SCOPE: "iam.authz.scope",
  ASSIGNMENT: "iam.authz.assignment",
  POLICY: "iam.authz.policy",
  ACCESS_REQUEST: "iam.governance.request",
  SOD: "iam.governance.sod",
  BREAK_GLASS: "iam.governance.breakglass",
  DELEGATION: "iam.governance.delegation",
  REVIEW: "iam.governance.review",
  RISK: "iam.risk.policy",
  SESSION: "iam.authn.session",
  AUDIT: "iam.audit.event",
  HR_SYNC: "iam.identity.hrsync",
  WEBHOOK: "iam.integration.webhook",
} as const;

/**
 * 본인의 관리 범위 (GET /api/v1/me/admin-scope). 메뉴·화면 구성에만 쓰고, 실제 허용 여부는 API 가 판정한다.
 * global 이 아니면 조직 단위 관리자처럼 orgIds 안의 조직에만 권한이 닿는다.
 */
export type AdminScope = {
  global: boolean;
  orgIds: number[];
  resources: { resource: string; actions: string[] }[];
};

export function can(scope: AdminScope, resource: string, action = "READ"): boolean {
  return scope.resources.some((r) => r.resource === resource && r.actions.includes(action));
}

/** 조회할 수 있는 리소스 키 (메뉴 노출용) */
export function readableResources(scope: AdminScope): string[] {
  return scope.resources.filter((r) => r.actions.includes("READ")).map((r) => r.resource);
}
