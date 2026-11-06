package com.didrakon.iam.authn.event

import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.sql.Timestamp
import java.time.Clock
import java.time.Instant

/** AUTHENTICATION_EVENT.event_type */
enum class AuthenticationEventType { LOGIN, LOGOUT, MFA, PASSWORD_CHANGE, FAILED_LOGIN }

enum class AuthenticationResult { SUCCESS, FAILURE, CHALLENGE }

/** 로그인·로그아웃·MFA 시도 기록. 대량 적재 테이블이라 JDBC 로 바로 쓴다 */
@Component
class AuthenticationEventWriter(
    private val jdbcTemplate: JdbcTemplate,
    private val clock: Clock,
) {
    fun write(
        type: AuthenticationEventType,
        result: AuthenticationResult,
        subjectId: Long? = null,
        identityId: Long? = null,
        ipAddress: String? = null,
        userAgent: String? = null,
        failureReason: String? = null,
    ) {
        jdbcTemplate.update(
            """
            INSERT INTO authentication_event (subject_id, identity_id, event_type, result, ip_address, user_agent, failure_reason, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            subjectId, identityId, type.name, result.name, ipAddress, userAgent?.take(500), failureReason?.take(1000),
            Timestamp.from(clock.instant()),
        )
    }

    /** [since] 이후 이 subject 의 같은 유형·결과·사유 기록 수 (셀프 재설정 시도 제한에 쓴다) */
    fun countSince(subjectId: Long, type: AuthenticationEventType, result: AuthenticationResult, failureReason: String, since: Instant): Int =
        jdbcTemplate.queryForObject(
            """
            SELECT COUNT(*) FROM authentication_event
            WHERE subject_id = ? AND created_at >= ? AND event_type = ? AND result = ? AND failure_reason = ?
            """,
            Int::class.java, subjectId, Timestamp.from(since), type.name, result.name, failureReason,
        ) ?: 0
}

/*
 * authn 이 발행하는 도메인 이벤트. audit 가 LOGIN·LOGOUT 감사 기록으로 남긴다.
 */

data class LoginSucceededEvent(val subjectId: Long, val identityId: Long, val loginSessionId: Long, val ipAddress: String?)

/** subjectId 는 계정을 찾지 못했으면 null. 사유는 계정 존재 여부가 드러나지 않는 수준으로만 남긴다 */
data class LoginFailedEvent(val loginId: String, val subjectId: Long?, val reason: String, val ipAddress: String?)

data class LoggedOutEvent(val subjectId: Long, val loginSessionId: Long?)

data class MfaVerifiedEvent(val subjectId: Long, val success: Boolean)

/** 로그인 화면의 셀프 비밀번호 재설정(인증 앱 코드 확인). subjectId 는 계정을 찾지 못했으면 null */
data class PasswordResetEvent(val loginId: String, val subjectId: Long?, val success: Boolean, val reason: String, val ipAddress: String?)

/** 패스키 등록·삭제. [credentialId] 는 base64url */
data class PasskeyChangedEvent(val subjectId: Long, val credentialId: String, val label: String, val added: Boolean)
