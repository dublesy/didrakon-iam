package com.didrakon.iam.audit.record

import com.didrakon.iam.common.context.RequestContextHolder
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import java.sql.Timestamp
import java.time.Clock

/** AUDIT_EVENT.event_type */
enum class AuditEventType { LOGIN, LOGOUT, ROLE_CHANGE, PERMISSION_CHANGE, MEMBERSHIP_CHANGE, JIT, POLICY_CHANGE, DATA_ACCESS }

/** 감사 이벤트 한 건. before·after 는 JSON 으로 직렬화된다 */
data class AuditRecord(
    val eventType: AuditEventType,
    val targetSubjectId: Long?,
    val resourceType: String?,
    val resourceId: String?,
    val action: String,
    val before: Any? = null,
    val after: Any? = null,
    val reason: String? = null,
    /** 지정하지 않으면 요청 컨텍스트의 행위자 */
    val actorSubjectId: Long? = null,
)

/**
 * AUDIT_EVENT 에 쓴다. 대량 적재 테이블이라 JPA 를 거치지 않는다.
 * 호출한 쪽 트랜잭션에서 실행되므로 업무 변경과 함께 커밋·롤백된다.
 */
@Component
class AuditEventWriter(
    private val jdbcTemplate: JdbcTemplate,
    private val jsonMapper: JsonMapper,
    private val clock: Clock,
) {
    fun write(record: AuditRecord) {
        val context = RequestContextHolder.current()
        jdbcTemplate.update(
            """
            INSERT INTO audit_event (
                actor_subject_id, target_subject_id, event_type, resource_type, resource_id, action,
                before_value, after_value, reason, trace_id, ip_address, device_id, user_agent, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            record.actorSubjectId ?: context?.actorSubjectId,
            record.targetSubjectId,
            record.eventType.name,
            record.resourceType,
            record.resourceId,
            record.action,
            record.before?.let(jsonMapper::writeValueAsString),
            record.after?.let(jsonMapper::writeValueAsString),
            record.reason?.take(1000),
            context?.traceId,
            context?.ipAddress,
            context?.deviceId,
            context?.userAgent?.take(500),
            Timestamp.from(clock.instant()),
        )
    }
}
