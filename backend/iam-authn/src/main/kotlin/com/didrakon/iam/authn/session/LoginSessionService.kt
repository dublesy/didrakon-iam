package com.didrakon.iam.authn.session

import com.didrakon.iam.authn.token.TokenRevoker
import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.common.crypto.sha256Hex
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.event.AdminChangeEvent
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

@Service
@Transactional
class LoginSessionService(
    private val sessionRepository: LoginSessionRepository,
    private val tokenRevoker: TokenRevoker,
    private val properties: AuthnProperties,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /** [sessionKey] 는 브라우저 세션에만 두고 DB 에는 hash 만 남긴다 */
    fun open(
        sessionKey: String,
        subjectId: Long,
        identityId: Long,
        level: AuthenticationLevel,
        ipAddress: String?,
        userAgent: String?,
    ): LoginSession {
        val now = clock.instant()
        return sessionRepository.save(
            LoginSession(sha256Hex(sessionKey), subjectId, identityId, level, now, now.plus(properties.sessionTimeout), ipAddress, userAgent?.take(500)),
        )
    }

    fun upgradeToMfa(sessionKey: String) {
        sessionRepository.findBySessionKeyHash(sha256Hex(sessionKey))?.upgradeTo(AuthenticationLevel.MFA, clock.instant())
    }

    /** 로그아웃. 이 세션에서 다른 시스템에 발급한 토큰도 함께 회수한다 (SSO 로그아웃) */
    fun close(sessionKey: String): LoginSession? =
        sessionRepository.findBySessionKeyHash(sha256Hex(sessionKey))?.also { end(it) }

    /** 관리자 강제 종료. 해당 브라우저의 다음 요청에서 로그아웃된다 */
    fun revoke(sessionId: Long) {
        val session = sessionRepository.findByIdOrNull(sessionId) ?: throw NotFoundException("로그인 세션", sessionId)
        end(session)
    }

    /** 사용 안 함·퇴사: 이 사용자의 모든 로그인 세션을 끝내고 발급한 토큰을 모두 회수한다 */
    fun revokeAll(subjectId: Long) {
        sessionRepository.findBySubjectIdAndStatus(subjectId, LoginSessionStatus.ACTIVE).forEach { it.revoke() }
        tokenRevoker.revokeBySubject(subjectId)
    }

    /** 관리자의 "모든 세션 끊기". [revokeAll] 과 같고, 감사 기록을 남긴다. 끊은 세션 수 */
    fun revokeAllByAdmin(subjectId: Long): Int {
        val count = activeSessions(subjectId).size
        revokeAll(subjectId)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "REVOKE_SESSIONS", null, mapOf("sessions" to count)))
        return count
    }

    private fun end(session: LoginSession) {
        if (session.status == LoginSessionStatus.ACTIVE) session.revoke()
        tokenRevoker.revokeBySession(session.requireId())
    }

    /** 본인이 고른 "다른 기기에서 모두 로그아웃". 지금 브라우저의 세션([currentSessionKey])만 남긴다. 끝낸 세션 목록 */
    fun revokeOthers(subjectId: Long, currentSessionKey: String): List<LoginSession> {
        val current = sha256Hex(currentSessionKey)
        return sessionRepository.findBySubjectIdAndStatus(subjectId, LoginSessionStatus.ACTIVE)
            .filter { it.sessionKeyHash != current }
            .onEach { end(it) }
    }

    @Transactional(readOnly = true)
    fun isValid(sessionKey: String): Boolean =
        sessionRepository.findBySessionKeyHash(sha256Hex(sessionKey))?.isValidAt(clock.instant()) ?: false

    /**
     * refresh token 으로 새 토큰을 줄 수 있는가: 이 인가가 나온 로그인 세션이 아직 유효해야 한다 (절대 만료·로그아웃·회수).
     * 이것이 없으면 refresh 할 때마다 만료가 다시 늘어나 로그인 세션 상한(8시간)을 넘겨 계속 토큰을 받는다.
     * 로그인 세션과 연결되지 않은 인가는 막지 않는다
     */
    @Transactional(readOnly = true)
    fun allowsRefresh(authorizationId: String): Boolean {
        val sessionIds = tokenRevoker.linkedSessionIds(authorizationId)
        if (sessionIds.isEmpty()) return true
        val now = clock.instant()
        return sessionRepository.findAllById(sessionIds).any { it.isValidAt(now) }
    }

    /** 이 브라우저(User-Agent)로 로그인한 적이 있는가. 기기 식별은 User-Agent 수준이다 */
    @Transactional(readOnly = true)
    fun hasUsedDevice(subjectId: Long, userAgent: String?): Boolean? =
        userAgent?.let { sessionRepository.existsBySubjectIdAndUserAgent(subjectId, it.take(500)) }

    @Transactional(readOnly = true)
    fun activeSessions(subjectId: Long): List<LoginSession> =
        sessionRepository.findBySubjectIdAndStatus(subjectId, LoginSessionStatus.ACTIVE).filter { it.isValidAt(clock.instant()) }
}
