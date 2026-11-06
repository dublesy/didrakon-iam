package com.didrakon.iam.authn.apikey

import com.didrakon.iam.common.crypto.randomUrlSafe
import com.didrakon.iam.common.crypto.sha256Hex
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import com.didrakon.iam.identity.subject.SubjectRepository
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 정적 API 키. 원문은 발급 시 한 번만 보여주고 hash 만 저장한다 */
@Entity
@Table(name = "api_key")
class ApiKey(
    subjectId: Long,
    keyHash: String,
    keyName: String,
    issuedAt: Instant,
    expireAt: Instant?,
    clientId: Long? = null,
    scopeExpression: String? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "api_key_id")
    override val id: Long? = null

    /** 키 소유 subject. 키로 들어온 요청은 이 subject 로 판정한다 */
    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "client_id", updatable = false)
    val clientId: Long? = clientId

    @Column(name = "key_hash", nullable = false, length = 64, updatable = false)
    val keyHash: String = keyHash

    @Column(name = "key_name", nullable = false, length = 200)
    var keyName: String = keyName
        protected set

    @Column(name = "scope_expression", columnDefinition = "json")
    var scopeExpression: String? = scopeExpression
        protected set

    @Column(name = "issued_at", nullable = false, updatable = false)
    val issuedAt: Instant = issuedAt

    @Column(name = "expire_at")
    var expireAt: Instant? = expireAt
        protected set

    @Column(name = "last_used_at")
    var lastUsedAt: Instant? = null
        protected set

    @Column(name = "revoked", nullable = false)
    var revoked: Boolean = false
        protected set

    @Column(name = "revoked_at")
    var revokedAt: Instant? = null
        protected set

    /** 폐기한 subject. 사용 중지·퇴사로 한꺼번에 폐기되면 비어 있다 */
    @Column(name = "revoked_by")
    var revokedBy: Long? = null
        protected set

    fun isUsableAt(now: Instant): Boolean = !revoked && (expireAt?.isAfter(now) ?: true)

    internal fun markUsed(now: Instant) {
        lastUsedAt = now
    }

    internal fun revoke(at: Instant, by: Long?) {
        if (revoked) return
        revoked = true
        revokedAt = at
        revokedBy = by
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

interface ApiKeyRepository : JpaRepository<ApiKey, Long> {
    fun findByKeyHash(keyHash: String): ApiKey?

    fun findBySubjectId(subjectId: Long): List<ApiKey>
}

data class IssuedApiKey(val apiKey: ApiKey, val rawKey: String)

@Service
@Transactional
class ApiKeyService(
    private val apiKeyRepository: ApiKeyRepository,
    private val subjectRepository: SubjectRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /** 발급·폐기는 감사 기록(누가 누구에게)을 남긴다. 키 원문과 hash 는 남기지 않는다 */
    fun issue(subjectId: Long, keyName: String, expireAt: Instant? = null, clientId: Long? = null): IssuedApiKey {
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        val now = clock.instant()
        if (expireAt != null && !expireAt.isAfter(now)) throw BusinessRuleException("만료 시각은 지금 이후여야 합니다")
        val rawKey = KEY_PREFIX + randomUrlSafe(32)
        val apiKey = apiKeyRepository.save(ApiKey(subjectId, sha256Hex(rawKey), keyName, now, expireAt, clientId))
        eventPublisher.publishEvent(AdminChangeEvent(AUDIT_TARGET, apiKey.requireId(), "ISSUE", null, snapshot(apiKey), subjectId))
        return IssuedApiKey(apiKey, rawKey)
    }

    /** subject 의 API 키 (폐기·만료 포함). 최근 발급 순 */
    @Transactional(readOnly = true)
    fun list(subjectId: Long): List<ApiKey> = apiKeyRepository.findBySubjectId(subjectId).sortedByDescending { it.issuedAt }

    /** 유효한 키면 마지막 사용 시각을 남기고 돌려준다 */
    fun authenticate(rawKey: String): ApiKey? {
        if (!rawKey.startsWith(KEY_PREFIX)) return null
        val now = clock.instant()
        return apiKeyRepository.findByKeyHash(sha256Hex(rawKey))?.takeIf { it.isUsableAt(now) }?.also { it.markUsed(now) }
    }

    /** 사용 안 함·퇴사: 이 subject 의 API 키를 모두 폐기한다 */
    fun revokeAll(subjectId: Long) {
        val now = clock.instant()
        apiKeyRepository.findBySubjectId(subjectId).forEach { it.revoke(now, null) }
    }

    /** [revokedBy] 는 폐기한 관리자 */
    fun revoke(apiKeyId: Long, revokedBy: Long? = null) {
        val apiKey = apiKeyRepository.findByIdOrNull(apiKeyId) ?: throw NotFoundException("API 키", apiKeyId)
        if (apiKey.revoked) return
        val before = snapshot(apiKey)
        apiKey.revoke(clock.instant(), revokedBy)
        eventPublisher.publishEvent(AdminChangeEvent(AUDIT_TARGET, apiKeyId, "REVOKE", before, snapshot(apiKey), apiKey.subjectId))
    }

    private fun snapshot(apiKey: ApiKey) =
        mapOf("subjectId" to apiKey.subjectId, "keyName" to apiKey.keyName, "expireAt" to apiKey.expireAt, "revoked" to apiKey.revoked)

    companion object {
        private const val AUDIT_TARGET = "API_KEY"

        /** 유출 탐지 도구가 알아볼 수 있도록 붙이는 접두어 */
        const val KEY_PREFIX = "iam_"
    }
}
