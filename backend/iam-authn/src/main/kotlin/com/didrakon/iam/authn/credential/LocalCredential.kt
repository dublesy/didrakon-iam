package com.didrakon.iam.authn.credential

import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.hibernate.Hibernate
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Duration
import java.time.Instant

/** 자체 비밀번호. LOCAL IdP 의 IDENTITY 1건당 1건 (PK 공유) */
@Entity
@Table(name = "local_credential")
class LocalCredential(
    identityId: Long,
    passwordHash: String,
    passwordChangedAt: Instant,
    passwordExpireAt: Instant? = null,
) {
    @Id
    @Column(name = "identity_id")
    val identityId: Long = identityId

    /** PasswordEncoder 결과 ({id} 접두어 포함) */
    @Column(name = "password_hash", nullable = false)
    var passwordHash: String = passwordHash
        protected set

    @Column(name = "password_changed_at", nullable = false)
    var passwordChangedAt: Instant = passwordChangedAt
        protected set

    @Column(name = "password_expire_at")
    var passwordExpireAt: Instant? = passwordExpireAt
        protected set

    /** 관리자가 초기화한 비밀번호. 다음 로그인에서 본인이 바꿔야 한다 */
    @Column(name = "must_change_password", nullable = false)
    var mustChangePassword: Boolean = false
        protected set

    @Column(name = "failed_attempt_count", nullable = false)
    var failedAttemptCount: Int = 0
        protected set

    @Column(name = "locked_until")
    var lockedUntil: Instant? = null
        protected set

    fun isLockedAt(now: Instant): Boolean = lockedUntil?.isAfter(now) ?: false

    fun isExpiredAt(now: Instant): Boolean = passwordExpireAt?.let { !it.isAfter(now) } ?: false

    /** 실패가 [maxAttempts] 번 쌓이면 [lockDuration] 동안 잠그고 횟수를 0 으로 되돌린다 */
    internal fun recordFailure(now: Instant, maxAttempts: Int, lockDuration: Duration) {
        failedAttemptCount += 1
        if (failedAttemptCount >= maxAttempts) {
            lockedUntil = now.plus(lockDuration)
            failedAttemptCount = 0
        }
    }

    internal fun recordSuccess() {
        failedAttemptCount = 0
        lockedUntil = null
    }

    internal fun changePassword(newHash: String, now: Instant, expireAt: Instant?, mustChange: Boolean) {
        passwordHash = newHash
        passwordChangedAt = now
        passwordExpireAt = expireAt
        mustChangePassword = mustChange
        recordSuccess()
    }

    /** 만료되었거나 관리자 초기화 뒤라 로그인 전에 바꿔야 하는가 */
    fun needsChangeAt(now: Instant): Boolean = mustChangePassword || isExpiredAt(now)

    /** 관리자가 정한 첫 비밀번호. 다음 로그인에서 본인이 바꿔야 한다 */
    internal fun requirePasswordChange() {
        mustChangePassword = true
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is LocalCredential || Hibernate.getClass(this) != Hibernate.getClass(other)) return false
        return identityId == other.identityId
    }

    override fun hashCode(): Int = identityId.hashCode()
}

interface LocalCredentialRepository : JpaRepository<LocalCredential, Long>
