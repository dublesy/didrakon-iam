package com.didrakon.iam.authn.session

import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant

/** IdP 로그인 세션. 여러 클라이언트의 SSO 에 걸친다. 외부에 노출되는 세션 키는 hash 로만 저장한다 */
@Entity
@Table(name = "login_session")
class LoginSession(
    sessionKeyHash: String,
    subjectId: Long,
    identityId: Long,
    authenticationLevel: AuthenticationLevel,
    loginAt: Instant,
    expireAt: Instant,
    ipAddress: String? = null,
    userAgent: String? = null,
    deviceId: String? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "session_id")
    override val id: Long? = null

    @Column(name = "session_key_hash", nullable = false, length = 64, updatable = false)
    val sessionKeyHash: String = sessionKeyHash

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "identity_id", nullable = false, updatable = false)
    val identityId: Long = identityId

    @Column(name = "device_id", length = 200, updatable = false)
    val deviceId: String? = deviceId

    @Column(name = "ip_address", length = 45, updatable = false)
    val ipAddress: String? = ipAddress

    @Column(name = "user_agent", length = 500, updatable = false)
    val userAgent: String? = userAgent

    @Enumerated(EnumType.STRING)
    @Column(name = "authentication_level", nullable = false, length = 30)
    var authenticationLevel: AuthenticationLevel = authenticationLevel
        protected set

    @Column(name = "login_at", nullable = false, updatable = false)
    val loginAt: Instant = loginAt

    @Column(name = "expire_at", nullable = false)
    var expireAt: Instant = expireAt
        protected set

    @Column(name = "last_activity_at", nullable = false)
    var lastActivityAt: Instant = loginAt
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: LoginSessionStatus = LoginSessionStatus.ACTIVE
        protected set

    fun isValidAt(now: Instant): Boolean = status == LoginSessionStatus.ACTIVE && expireAt.isAfter(now)

    internal fun upgradeTo(level: AuthenticationLevel, now: Instant) {
        authenticationLevel = level
        lastActivityAt = now
    }

    internal fun revoke() {
        status = LoginSessionStatus.REVOKED
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class AuthenticationLevel { PASSWORD, MFA, CERTIFICATE }

enum class LoginSessionStatus { ACTIVE, EXPIRED, REVOKED }

interface LoginSessionRepository : JpaRepository<LoginSession, Long> {
    fun findBySessionKeyHash(sessionKeyHash: String): LoginSession?

    fun findBySubjectIdAndStatus(subjectId: Long, status: LoginSessionStatus): List<LoginSession>

    fun existsBySubjectIdAndUserAgent(subjectId: Long, userAgent: String): Boolean
}
