/**
 * IAM API 응답 타입. 백엔드 DTO 와 1:1 이다
 * (backend/iam-app/src/main/kotlin/com/didrakon/iam/api/** 의 *Response).
 */

export type Page<T> = { items: T[]; page: number; size: number; total: number };

// ---------- identity ----------

export type User = {
  subjectId: number;
  /** EMPLOYEE(내부 임직원) · EXTERNAL(외부 사용자, 사번 없음) */
  userKind: string;
  empNo: string | null;
  name: string;
  email: string | null;
  phone: string | null;
  status: string;
  employmentStatus: string;
  hireDate: string | null;
  /** 퇴사일. 상태가 RETIRED 가 아니면 퇴사 예정일 */
  retireDate: string | null;
};

/** LOCAL 로그인 계정의 비밀번호·잠금 상태. 로그인 계정이 없으면 API 가 null 을 준다 */
export type CredentialState = {
  locked: boolean;
  /** 잠금이 풀리는 시각. 잠기지 않았으면 null */
  lockedUntil: string | null;
  mustChangePassword: boolean;
  passwordExpireAt: string | null;
};

export const ORG_TYPES = ["GROUP", "COMPANY", "DIVISION", "DEPARTMENT", "TEAM", "CENTER"] as const;
export const ORG_TYPE_LABELS: Record<string, string> = {
  GROUP: "그룹",
  COMPANY: "법인",
  DIVISION: "본부",
  DEPARTMENT: "부서",
  TEAM: "팀",
  CENTER: "센터",
};

export type Organization = {
  orgId: number;
  orgCode: string;
  orgName: string;
  orgType: string;
  parentOrgId: number | null;
  companyOrgId: number | null;
  orgLevel: number;
  isActive: boolean;
};

export const MEMBERSHIP_TYPES = ["PRIMARY", "SECONDARY", "TEMPORARY"] as const;
export const USER_KINDS = ["EMPLOYEE", "EXTERNAL"] as const;
export const MEMBERSHIP_TYPE_LABELS: Record<string, string> = { PRIMARY: "주 소속", SECONDARY: "겸직", TEMPORARY: "임시" };

export type Membership = {
  membershipId: number;
  subjectId: number;
  orgId: number;
  membershipType: string;
  jobTitle: string | null;
  jobGrade: string | null;
  isManager: boolean;
  validFrom: string;
};

export const GROUP_TYPES = ["STATIC", "DYNAMIC"] as const;

export type Group = { groupId: number; groupCode: string; groupName: string; groupType: string; ruleExpression: string | null; isActive: boolean };
export type GroupMember = { subjectId: number; sourceType: string; validFrom: string };

// ---------- authz ----------

export const ROLE_TYPES = ["SYSTEM", "BUSINESS", "CUSTOM", "PRIVILEGED"] as const;

export type Role = {
  roleId: number;
  roleCode: string;
  roleName: string;
  roleType: string;
  isSensitive: boolean;
  isPrivileged: boolean;
  isActive: boolean;
  priority: number;
};

export const ACTIONS = ["READ", "CREATE", "UPDATE", "DELETE", "EXECUTE", "APPROVE", "EXPORT"] as const;
export const EFFECTS = ["ALLOW", "DENY"] as const;

export type Permission = {
  permissionId: number;
  permissionCode: string;
  permissionName: string;
  resourceId: number;
  action: string;
  effect: string;
  isActive: boolean;
};

export const SCOPE_TYPES = ["ORGANIZATION", "RESOURCE", "PROJECT", "DATA"] as const;

export type Scope = {
  scopeId: number;
  scopeCode: string;
  scopeName: string;
  scopeType: string;
  orgId: number | null;
  resourceId: number | null;
  includeDescendants: boolean;
  isActive: boolean;
};

export type RoleDetail = {
  role: Role;
  permissions: { rolePermissionId: number; permission: Permission; scope: Scope }[];
};

export const RESOURCE_TYPES = ["SYSTEM", "MENU", "API", "DATA", "BUTTON", "DOCUMENT"] as const;
export const SENSITIVITIES = ["PUBLIC", "INTERNAL", "CONFIDENTIAL", "SECRET"] as const;

export type Resource = {
  resourceId: number;
  clientId: number;
  parentResourceId: number | null;
  resourceKey: string;
  resourceName: string;
  resourceType: string;
  sensitivity: string;
  isActive: boolean;
  resourcePath: string | null;
};

export type Client = {
  clientId: number;
  clientCode: string;
  clientName: string;
  clientType: string;
  requireMfa: boolean;
  isActive: boolean;
  /** OIDC Back-Channel Logout 수신 주소 */
  backchannelLogoutUri: string | null;
  /** 토큰에 role = "authenticated" 를 넣는다 (Supabase Third-Party Auth) */
  supabaseRoleClaim: boolean;
  /** 앱 런처 시작 주소. 있으면 IAM 홈의 내 앱 목록에 나온다 */
  homeUrl: string | null;
  redirectUris: string[];
  /** RP 로그아웃 후 돌아갈 수 있는 주소 */
  postLogoutRedirectUris: string[];
  /** openid·profile 포함 */
  scopes: string[];
  /** 비밀값이 있는 클라이언트. false 면 PKCE 를 쓰는 public client */
  confidential: boolean;
};

export type Assignment = {
  assignmentId: number;
  roleId: number;
  scopeId: number;
  sourceType: string;
  sourceId: number | null;
  validFrom: string;
  validUntil: string | null;
  reviewRequired: boolean;
};

export type OrganizationRole = {
  orgRoleId: number;
  orgId: number;
  roleId: number;
  scopeId: number;
  applyToDescendants: boolean;
  isActive: boolean;
};

export type GroupRole = { groupRoleId: number; groupId: number; roleId: number; scopeId: number };

export const POLICY_TYPES = ["AUTHORIZATION", "SECURITY", "DATA", "RISK"] as const;
export const POLICY_EFFECTS = ["ALLOW", "DENY", "CHALLENGE", "REQUIRE_APPROVAL"] as const;
export const POLICY_EFFECT_LABELS: Record<string, string> = {
  ALLOW: "조건부 허용",
  DENY: "거부",
  CHALLENGE: "추가 인증",
  REQUIRE_APPROVAL: "승인 필요",
};
export const ATTRIBUTE_SOURCES = ["SUBJECT", "RESOURCE", "CONTEXT", "RELATION", "SESSION"] as const;
export const OPERATORS = ["EQ", "NE", "IN", "NOT_IN", "GT", "LT", "BETWEEN", "MATCH", "EXISTS"] as const;

export type Policy = { policyId: number; policyCode: string; policyName: string; policyType: string; effect: string; isActive: boolean; priority: number };

export type PolicyRule = {
  ruleGroup: number;
  attributeSource: string;
  attributeName: string;
  operator: string;
  attributeValue: string | null;
  ruleOrder: number;
};

export type PolicyDetail = {
  policy: Policy;
  targets: { policyTargetId: number; permissionId: number | null; resourceId: number | null; roleId: number | null }[];
  versions: { policyVersionId: number; version: number; status: string; changeReason: string | null; createdAt: string; rules: PolicyRule[] }[];
  exceptions: { exceptionId: number; subjectId: number | null; resourceId: number | null; reason: string; validFrom: string; validUntil: string | null }[];
};

// ---------- governance ----------

export const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"] as const;

export type AccessRequest = {
  requestId: number;
  requestType: string;
  subjectId: number;
  roleId: number;
  scopeId: number;
  reason: string;
  riskLevel: string;
  requestedStart: string;
  requestedEnd: string;
  status: string;
};

export type RoleConflict = {
  conflictId: number;
  roleIdA: number;
  roleIdB: number;
  severity: string;
  description: string | null;
  isActive: boolean;
  exceptions: { exceptionId: number; subjectId: number; approvedBy: number; reason: string; validUntil: string | null }[];
};

// ---------- authn·audit ----------

export type LoginSession = { sessionId: number; authenticationLevel: string; ipAddress: string | null; loginAt: string; expireAt: string };

export const AUDIT_EVENT_TYPES = ["LOGIN", "LOGOUT", "ROLE_CHANGE", "PERMISSION_CHANGE", "MEMBERSHIP_CHANGE", "JIT", "POLICY_CHANGE", "DATA_ACCESS"] as const;

export type AuditEvent = {
  eventId: number;
  eventType: string;
  actorSubjectId: number | null;
  targetSubjectId: number | null;
  resourceType: string | null;
  resourceId: string | null;
  action: string | null;
  beforeValue: string | null;
  afterValue: string | null;
  reason: string | null;
  traceId: string | null;
  ipAddress: string | null;
  createdAt: string;
};

export type RoleHistory = {
  historyId: number;
  roleId: number;
  changeType: string;
  assignmentId: number | null;
  changedBy: number | null;
  reason: string | null;
  changedAt: string;
};

export const RISK_TYPES = ["LOGIN", "DATA_ACCESS", "JIT", "PRIVILEGE"] as const;
export const RISK_ACTIONS = ["ALLOW", "CHALLENGE", "APPROVAL", "DENY"] as const;
export const RISK_SIGNALS = ["NEW_DEVICE", "UNUSUAL_TIME", "FAILED_LOGIN_BURST", "MASS_ACCESS", "FOREIGN_IP"] as const;

export type RiskPolicy = {
  riskPolicyId: number;
  policyName: string;
  riskType: string;
  conditionExpression: string;
  riskScore: number;
  action: string;
  isActive: boolean;
};

export type RiskAssessment = { assessmentId: number; requestId: number | null; riskScore: number; riskLevel: string; decision: string; assessedAt: string };
export type RiskSignal = { riskSignalId: number; signalType: string; riskScore: number; details: string | null; detectedAt: string };
export type SubjectRisk = { assessments: RiskAssessment[]; signals: RiskSignal[] };

export type MfaMethod = { methodId: number; methodType: string; registeredAt: string; lastUsedAt: string | null };

/** 등록한 패스키. credentialId 는 base64url */
export type Passkey = { credentialId: string; label: string; createdAt: string | null; lastUsedAt: string | null };

/** HR 연동 레코드 처리 결과. 화면 표시 순서이기도 하다 */
export const HR_SYNC_ACTIONS = [
  "CREATED",
  "UPDATED",
  "TRANSFERRED",
  "MEMBERSHIP_UPDATED",
  "ON_LEAVE",
  "RETURNED",
  "RETIRED",
  "RETIRE_SCHEDULED",
  "RETIRE_CANCELLED",
  "SKIPPED",
  "UNCHANGED",
  "ERROR",
] as const;

export type HrRecordResult = { empNo: string | null; subjectId: number | null; actions: string[]; message: string | null };
export type HrMissingUser = { subjectId: number; empNo: string; name: string; status: string };
export type HrSyncResult = {
  runId: number;
  dryRun: boolean;
  counts: Record<string, number>;
  records: HrRecordResult[];
  /** reportMissing 을 요청하지 않았으면 null */
  missing: HrMissingUser[] | null;
};

export type HrSyncRun = {
  runId: number;
  dryRun: boolean;
  startedAt: string;
  finishedAt: string;
  actorSubjectId: number | null;
  total: number;
  counts: Record<string, number>;
  errors: { empNo: string | null; message: string }[];
  missingCount: number | null;
};

// ---------- webhook ----------

/** 구독할 수 있는 이벤트 유형. "*" 는 전체 */
export const WEBHOOK_EVENT_TYPES = [
  "user.status_changed",
  "membership.changed",
  "group_membership.changed",
  "role_assignment.changed",
  "access_request.changed",
  "config.changed",
  "organization.moved",
  "user.credential_changed",
  "access_review.changed",
] as const;

/** 비밀값은 담기지 않는다 (만들 때·교체할 때만 따로 받는다) */
export type Webhook = {
  webhookId: number;
  name: string;
  url: string;
  eventTypes: string[];
  isActive: boolean;
  createdAt: string;
  createdBy: number | null;
  /** 최근 7일 동안 만든 전달의 상태별 수 */
  recentCounts: Record<string, number>;
};

export const WEBHOOK_DELIVERY_STATUSES = ["PENDING", "SUCCEEDED", "FAILED", "DEAD"] as const;

export type WebhookDelivery = {
  deliveryId: number;
  webhookId: number;
  eventId: string;
  eventType: string;
  status: string;
  attempts: number;
  nextAttemptAt: string;
  lastStatusCode: number | null;
  lastError: string | null;
  createdAt: string;
  deliveredAt: string | null;
};

export const REVIEW_SCOPE_TYPES = ["ALL", "ORGANIZATION", "ROLE"] as const;
/** 접근 재검토 대상 출처. 조직·그룹 할당은 역할 규칙을 바꿔 검토하므로 고를 수 없다 */
export const REVIEW_SOURCES = ["DIRECT", "JIT", "DELEGATION", "BREAK_GLASS"] as const;
export const REVIEW_DEFAULT_SOURCES: readonly string[] = ["DIRECT", "JIT", "DELEGATION"];
export const REVIEW_DECISIONS = ["PENDING", "KEEP", "REVOKE"] as const;

export type AccessReviewCampaign = {
  campaignId: number;
  name: string;
  scopeType: string;
  scopeOrgId: number | null;
  scopeRoleId: number | null;
  includeDescendants: boolean;
  privilegedOnly: boolean;
  sources: string[];
  dueAt: string;
  onOverdue: string;
  /** 기한이 지나면 상위 조직 관리자에게 넘기고 더 기다리는 날수. null 이면 이관 없음 */
  escalationDays: number | null;
  escalatedAt: string | null;
  /** 이관까지 마친 뒤 닫는 시각 (이관이 없으면 dueAt) */
  finalDueAt: string;
  status: string;
  createdBy: number | null;
  createdAt: string;
  closedAt: string | null;
  total: number;
  pending: number;
  kept: number;
  revoked: number;
};

/** 이름·역할·범위는 캠페인을 만든 시점 값이다 (증적) */
export type AccessReviewItem = {
  itemId: number;
  campaignId: number;
  assignmentId: number;
  subjectId: number;
  subjectName: string;
  empNo: string | null;
  orgName: string | null;
  roleId: number;
  roleCode: string;
  roleName: string;
  isPrivileged: boolean;
  scopeId: number;
  scopeName: string;
  sourceType: string;
  reviewerId: number | null;
  reviewerName: string | null;
  /** 기한 경과로 상위 관리자에게 넘긴 시각과 원래 검토자 (원래 검토자가 없었으면 null) */
  escalatedAt: string | null;
  escalatedFromName: string | null;
  reviewRequired: boolean;
  assignmentValidFrom: string;
  assignmentValidUntil: string | null;
  decision: string;
  decidedBy: number | null;
  decidedByName: string | null;
  decidedAt: string | null;
  comment: string | null;
};

export type AccessReviewDetail = { campaign: AccessReviewCampaign; items: AccessReviewItem[] };

export type MyAccessReviewItem = { campaignName: string; dueAt: string; item: AccessReviewItem };

/** 사용자 상세의 로그인 계정 (GET /api/v1/users/{id}/credential). LOCAL 계정이 없으면 null */
export type LoginAccount = CredentialState & { loginId: string; passwordChangedAt: string };

/** 사용자의 2단계 인증 수단 (GET /api/v1/subjects/{id}/mfa). 비밀값은 오지 않는다 */
export type SubjectMfa = { methods: MfaMethod[]; passkeys: Passkey[] };

/** API 키 목록 항목. 키 원문은 발급 응답에서 한 번만 온다 */
export type ApiKey = {
  apiKeyId: number;
  keyName: string;
  issuedAt: string;
  expireAt: string | null;
  lastUsedAt: string | null;
  revoked: boolean;
  /** 폐기 시각. 예전에 폐기된 키는 비어 있다 */
  revokedAt: string | null;
};

// ---------- 거버넌스 운영 (비상 접근·위임·접근 요청 기록·내 권한 요청) ----------

export type ApprovalDecision = { approverId: number; approverName: string | null; status: string; comment: string | null; decidedAt: string };

/** 이름을 풀어 둔 접근 요청 (처리 기록·내 요청) */
export type AccessRequestView = {
  requestId: number;
  requestType: string;
  subjectId: number;
  subjectName: string | null;
  roleId: number;
  roleName: string | null;
  scopeId: number;
  scopeCode: string | null;
  reason: string;
  riskLevel: string;
  requestedStart: string;
  requestedEnd: string;
  status: string;
  createdAt: string;
  decisions: ApprovalDecision[];
  /** 처리가 끝난(승인·반려·취소·만료) 시각. 대기 중이거나 예전에 끝난 요청은 비어 있다 */
  closedAt: string | null;
};

export type BreakGlassPolicy = {
  policyId: number;
  policyName: string;
  roleId: number;
  roleName: string | null;
  scopeId: number;
  scopeCode: string | null;
  maxDurationMinutes: number;
  requireReason: boolean;
  requireApproval: boolean;
  requireMfa: boolean;
  isActive: boolean;
  /** 시작할 수 있는 그룹. 비어 있으면 누구나 */
  eligibleGroupId: number | null;
  eligibleGroupCode: string | null;
  eligibleGroupName: string | null;
};

/** revokedBy 가 있으면 그 사람이 끝냈고, 없으면 최대 시간이 지나 끝났다 */
export type BreakGlassSession = {
  sessionId: number;
  policyId: number;
  policyName: string | null;
  subjectId: number;
  subjectName: string | null;
  roleId: number | null;
  roleName: string | null;
  reason: string | null;
  startTime: string;
  endTime: string;
  status: string;
  requestId: number | null;
  revokedBy: number | null;
  revokedByName: string | null;
};

export type Delegation = {
  delegationId: number;
  delegatorId: number;
  delegatorName: string | null;
  delegateId: number;
  delegateName: string | null;
  roleId: number;
  roleName: string | null;
  scopeId: number;
  scopeCode: string | null;
  startTime: string;
  endTime: string;
  reason: string;
  status: string;
  createdAt: string;
};

export type MyDelegations = { given: Delegation[]; received: Delegation[] };

/** 내 권한 요청·위임 폼의 선택지 */
export type AccessOptions = {
  roles: { roleId: number; roleCode: string; roleName: string; isPrivileged: boolean }[];
  scopes: { scopeId: number; scopeCode: string; scopeName: string }[];
  delegatable: { roleId: number; roleName: string; scopeId: number; scopeCode: string }[];
};

/** 비상 접근 대상 그룹 선택지 (GET /api/v1/break-glass-policies/group-options) */
export type GroupOption = { groupId: number; groupCode: string; groupName: string };
