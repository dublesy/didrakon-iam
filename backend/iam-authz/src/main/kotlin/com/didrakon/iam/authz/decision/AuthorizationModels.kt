package com.didrakon.iam.authz.decision

import com.didrakon.iam.authz.role.PermissionAction

/** 권한 판정 요청 */
data class AuthorizationRequest(
    val subjectId: Long,
    val resourceId: Long,
    val action: PermissionAction,
    /** 대상 데이터가 속한 조직. ORGANIZATION scope 는 이 값이 있어야 매칭된다 */
    val orgId: Long? = null,
    /** ABAC CONTEXT 속성 (IP, 국가, 시각 등). 호출 측이 채운다 */
    val context: Map<String, Any?> = emptyMap(),
    /** ABAC SESSION 속성 (인증 수준 등). 호출 측이 채운다 */
    val session: Map<String, Any?> = emptyMap(),
    val sessionId: Long? = null,
    val traceId: String? = null,
)

/** 뒤에 올수록 강하다. 여러 결과가 나오면 가장 강한 것을 택한다 (deny-overrides) */
enum class Decision { ALLOW, CHALLENGE, REQUIRE_APPROVAL, DENY }

data class AuthorizationResult(
    val decision: Decision,
    val reason: String,
    /** 판정 근거 목록. 판정 로그의 explanation 에 그대로 남는다 */
    val explanation: List<String>,
    val matchedAssignmentId: Long? = null,
    val matchedRoleId: Long? = null,
    val matchedPermissionId: Long? = null,
    val matchedScopeId: Long? = null,
    val matchedPolicyId: Long? = null,
    val matchedRelationId: Long? = null,
    /** RBAC 이 허용해 위험 평가까지 간 판정만 값이 있다 */
    val riskScore: Int? = null,
)
