package com.didrakon.iam.authn.token

import org.springframework.context.ApplicationEventPublisher
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.sql.Timestamp
import java.time.Clock

/**
 * OAuth2 인가 기록(oauth2_authorization: code·access·refresh·id token 묶음)을 회수한다.
 * 기록을 지우면 refresh token 으로 새 토큰을 받을 수 없고, 토큰 검사(introspection)도 비활성으로 나온다.
 * 지운 인가의 연동 시스템에는 back-channel 로그아웃 토큰을 보낸다 ([BackChannelLogoutNotifier]).
 * 접근 토큰(JWT)은 서명만으로 검증되므로 만료(10분)까지는 남는다. 그 사이 권한 판정은 PDP 가 사용자 상태로 막는다.
 */
@Component
class TokenRevoker(
    private val jdbcTemplate: JdbcTemplate,
    private val logoutNotifier: BackChannelLogoutNotifier,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /** 인가 기록이 어느 로그인 세션에서 나왔는지 적어 둔다. 같은 인가가 다시 저장되어도 한 번만 남는다 */
    fun link(authorizationId: String, sessionId: Long, subjectId: Long) {
        jdbcTemplate.update(
            "INSERT IGNORE INTO login_session_authorization (authorization_id, session_id, subject_id, created_at) VALUES (?, ?, ?, ?)",
            authorizationId, sessionId, subjectId, Timestamp.from(clock.instant()),
        )
    }

    /** 이 인가가 나온 로그인 세션 ID. 세션과 연결되지 않은 인가(시스템 토큰 등)는 빈 목록 */
    fun linkedSessionIds(authorizationId: String): List<Long> =
        jdbcTemplate.queryForList("SELECT session_id FROM login_session_authorization WHERE authorization_id = ?", Long::class.java, authorizationId)
            .filterNotNull()

    /** 이 로그인 세션에서 발급한 토큰을 모두 회수한다. 회수한 인가 수 */
    fun revokeBySession(sessionId: Long): Int {
        val targets = logoutNotifier.targetsBySession(sessionId)
        val removed = jdbcTemplate.update(
            "DELETE FROM oauth2_authorization WHERE id IN (SELECT authorization_id FROM login_session_authorization WHERE session_id = ?)",
            sessionId,
        )
        jdbcTemplate.update("DELETE FROM login_session_authorization WHERE session_id = ?", sessionId)
        if (targets.isNotEmpty()) eventPublisher.publishEvent(BackChannelLogoutEvent(targets))
        return removed
    }

    /** 이 사용자에게 발급한 토큰을 모두 회수한다 (세션 연결이 없는 것까지). 회수한 인가 수 */
    fun revokeBySubject(subjectId: Long): Int {
        val targets = logoutNotifier.targetsBySubject(subjectId)
        val removed = jdbcTemplate.update("DELETE FROM oauth2_authorization WHERE principal_name = ?", subjectId.toString())
        jdbcTemplate.update("DELETE FROM login_session_authorization WHERE subject_id = ?", subjectId)
        if (targets.isNotEmpty()) eventPublisher.publishEvent(BackChannelLogoutEvent(targets))
        return removed
    }
}
