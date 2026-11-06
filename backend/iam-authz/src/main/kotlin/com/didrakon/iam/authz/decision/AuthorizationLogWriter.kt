package com.didrakon.iam.authz.decision

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import java.sql.Timestamp
import java.time.Instant

/** 판정 결과를 AUTHORIZATION_LOG 에 남긴다. 대량 적재 테이블이라 JPA 를 거치지 않고 JDBC 로 바로 쓴다 */
@Component
class AuthorizationLogWriter(
    private val jdbcTemplate: JdbcTemplate,
    private val jsonMapper: JsonMapper,
) {
    fun write(request: AuthorizationRequest, result: AuthorizationResult, decidedAt: Instant, evaluationTimeMs: Int) {
        jdbcTemplate.update(
            """
            INSERT INTO authorization_log (
                trace_id, subject_id, resource_id, action, scope_id, session_id, context,
                decision, decision_reason, matched_policy_id, matched_role_id, matched_permission_id,
                matched_assignment_id, matched_relation_id, risk_score, explanation, evaluation_time_ms, decided_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            request.traceId,
            request.subjectId,
            request.resourceId,
            request.action.name,
            result.matchedScopeId,
            request.sessionId,
            jsonMapper.writeValueAsString(request.context + ("orgId" to request.orgId)),
            result.decision.name,
            result.reason.take(1000),
            result.matchedPolicyId,
            result.matchedRoleId,
            result.matchedPermissionId,
            result.matchedAssignmentId,
            result.matchedRelationId,
            result.riskScore,
            jsonMapper.writeValueAsString(result.explanation),
            evaluationTimeMs,
            Timestamp.from(decidedAt),
        )
    }

    /** [since] 이후 이 subject 의 판정 횟수. 대량 조회(MASS_ACCESS) 위험 신호에 쓴다 */
    fun countSince(subjectId: Long, since: Instant): Long =
        jdbcTemplate.queryForObject(
            "SELECT COUNT(*) FROM authorization_log WHERE subject_id = ? AND decided_at >= ?",
            Long::class.java, subjectId, Timestamp.from(since),
        ) ?: 0
}
