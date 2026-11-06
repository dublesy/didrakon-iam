package com.didrakon.iam.authn.event

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.time.Instant

/** 인증 기록 한 줄 (본인의 최근 보안 활동 화면용) */
data class RecentAuthenticationEvent(
    val type: AuthenticationEventType,
    val result: AuthenticationResult,
    val ipAddress: String?,
    val userAgent: String?,
    val failureReason: String?,
    val at: Instant,
)

@Component
class AuthenticationEventReader(private val jdbcTemplate: JdbcTemplate) {
    /** 이 사용자의 최근 인증 기록 [limit] 건 (최신 순) */
    fun recent(subjectId: Long, limit: Int): List<RecentAuthenticationEvent> = jdbcTemplate.query(
        """
        SELECT event_type, result, ip_address, user_agent, failure_reason, created_at FROM authentication_event
        WHERE subject_id = ? ORDER BY created_at DESC, authentication_event_id DESC LIMIT ?
        """,
        { rs, _ ->
            RecentAuthenticationEvent(
                AuthenticationEventType.valueOf(rs.getString("event_type")),
                AuthenticationResult.valueOf(rs.getString("result")),
                rs.getString("ip_address"), rs.getString("user_agent"), rs.getString("failure_reason"),
                rs.getTimestamp("created_at").toInstant(),
            )
        },
        subjectId, limit,
    )
}
