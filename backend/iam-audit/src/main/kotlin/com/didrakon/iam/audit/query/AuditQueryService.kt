package com.didrakon.iam.audit.query

import com.didrakon.iam.audit.history.PolicyChangeHistory
import com.didrakon.iam.audit.history.PolicyChangeHistoryRepository
import com.didrakon.iam.audit.history.RoleChangeHistory
import com.didrakon.iam.audit.history.RoleChangeHistoryRepository
import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.common.error.BusinessRuleException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.sql.ResultSet
import java.sql.Timestamp
import java.time.Instant

/** 감사 이벤트 검색 조건. 기간은 필수이고 [from, to) 이다 */
data class AuditSearch(
    val from: Instant,
    val to: Instant,
    /** 행위자이거나 대상인 subject */
    val subjectId: Long? = null,
    val eventTypes: Set<AuditEventType> = emptySet(),
    val limit: Int = 100,
)

data class AuditEventView(
    val eventId: Long,
    val eventType: AuditEventType,
    val actorSubjectId: Long?,
    val targetSubjectId: Long?,
    val resourceType: String?,
    val resourceId: String?,
    val action: String?,
    val beforeValue: String?,
    val afterValue: String?,
    val reason: String?,
    val traceId: String?,
    val ipAddress: String?,
    val createdAt: Instant,
)

@Service
@Transactional(readOnly = true)
class AuditQueryService(
    private val jdbcTemplate: JdbcTemplate,
    private val roleHistoryRepository: RoleChangeHistoryRepository,
    private val policyHistoryRepository: PolicyChangeHistoryRepository,
) {
    /** 최신순. 기간 조건이 있어야 created_at 인덱스·파티션을 탄다 */
    fun search(search: AuditSearch): List<AuditEventView> {
        if (!search.from.isBefore(search.to)) throw BusinessRuleException("조회 시작 시각은 끝 시각보다 앞서야 합니다")
        if (search.limit !in 1..MAX_LIMIT) throw BusinessRuleException("조회 건수는 1~$MAX_LIMIT 건입니다")

        val conditions = mutableListOf("created_at >= ?", "created_at < ?")
        val args = mutableListOf<Any>(Timestamp.from(search.from), Timestamp.from(search.to))
        search.subjectId?.let {
            conditions.add("(actor_subject_id = ? OR target_subject_id = ?)")
            args.addAll(listOf(it, it))
        }
        if (search.eventTypes.isNotEmpty()) {
            conditions.add("event_type IN (${search.eventTypes.joinToString(",") { "?" }})")
            args.addAll(search.eventTypes.map { it.name })
        }
        args.add(search.limit)

        return jdbcTemplate.query(
            """
            SELECT event_id, event_type, actor_subject_id, target_subject_id, resource_type, resource_id, action,
                   before_value, after_value, reason, trace_id, ip_address, created_at
            FROM audit_event
            WHERE ${conditions.joinToString(" AND ")}
            ORDER BY created_at DESC, event_id DESC
            LIMIT ?
            """,
            { rs, _ -> rs.toView() },
            *args.toTypedArray(),
        )
    }

    fun roleHistory(subjectId: Long): List<RoleChangeHistory> =
        roleHistoryRepository.findBySubjectIdOrderByChangedAtDescIdDesc(subjectId)

    fun policyHistory(policyId: Long): List<PolicyChangeHistory> =
        policyHistoryRepository.findByPolicyIdOrderByChangedAtDescIdDesc(policyId)

    private fun ResultSet.toView() = AuditEventView(
        eventId = getLong("event_id"),
        eventType = AuditEventType.valueOf(getString("event_type")),
        actorSubjectId = getObject("actor_subject_id", java.lang.Long::class.java)?.toLong(),
        targetSubjectId = getObject("target_subject_id", java.lang.Long::class.java)?.toLong(),
        resourceType = getString("resource_type"),
        resourceId = getString("resource_id"),
        action = getString("action"),
        beforeValue = getString("before_value"),
        afterValue = getString("after_value"),
        reason = getString("reason"),
        traceId = getString("trace_id"),
        ipAddress = getString("ip_address"),
        createdAt = getTimestamp("created_at").toInstant(),
    )

    companion object {
        const val MAX_LIMIT = 1000
    }
}
