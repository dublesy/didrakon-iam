package com.didrakon.iam.authn.mfa

import com.didrakon.iam.common.crypto.randomBytes
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.event.AdminChangeEvent
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
import jakarta.persistence.LockModeType
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Lock
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.net.URLEncoder
import java.time.Clock
import java.time.Instant

/** 등록된 MFA 수단. 비밀값은 [SecretStore] 에 있고 여기에는 참조만 둔다 */
@Entity
@Table(name = "mfa_method")
class MfaMethod(
    subjectId: Long,
    methodType: MfaMethodType,
    secretReference: String?,
    registeredAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "mfa_method_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Enumerated(EnumType.STRING)
    @Column(name = "method_type", nullable = false, length = 30, updatable = false)
    val methodType: MfaMethodType = methodType

    @Column(name = "secret_reference", length = 500, updatable = false)
    val secretReference: String? = secretReference

    @Column(name = "is_primary", nullable = false)
    var isPrimary: Boolean = false
        protected set

    /** 등록 직후에는 false. 첫 코드 확인을 마쳐야 로그인에 쓴다 */
    @Column(name = "is_verified", nullable = false)
    var isVerified: Boolean = false
        protected set

    /** 마지막으로 통과한 TOTP 시간 구간. 같거나 이전 구간의 코드는 다시 받지 않는다 */
    @Column(name = "last_used_step")
    var lastUsedStep: Long? = null
        protected set

    @Column(name = "registered_at", nullable = false, updatable = false)
    val registeredAt: Instant = registeredAt

    /** 처음 쓰는 구간이면 기록하고 true, 이미 쓴 구간이면 false (재사용) */
    internal fun use(step: Long): Boolean {
        if (lastUsedStep?.let { step <= it } == true) return false
        lastUsedStep = step
        return true
    }

    internal fun confirm() {
        isVerified = true
        isPrimary = true
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class MfaMethodType { TOTP, SMS, EMAIL, FIDO2, PASSKEY }

interface MfaMethodRepository : JpaRepository<MfaMethod, Long> {
    fun findBySubjectId(subjectId: Long): List<MfaMethod>

    /** 같은 코드를 동시에 두 번 내도 한 번만 통과하도록 잠근다 */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select m from MfaMethod m where m.subjectId = :subjectId")
    fun findBySubjectIdForUpdate(@Param("subjectId") subjectId: Long): List<MfaMethod>
}

/** 등록 결과. 비밀값은 인증 앱 등록에만 쓰고 다시 보여주지 않는다 */
data class TotpEnrollment(val methodId: Long, val secretBase32: String, val otpauthUri: String)

@Service
@Transactional
class MfaService(
    private val methodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /**
     * TOTP 등록을 시작한다. [confirmTotp] 로 첫 코드를 확인해야 활성화된다.
     * 확인하지 않고 버려진 이전 등록은 지운다 (등록 시작마다 쌓이지 않게)
     */
    fun enrollTotp(subjectId: Long, accountLabel: String): TotpEnrollment {
        methodRepository.findBySubjectId(subjectId).filter { !it.isVerified }.forEach(::delete)
        val secret = randomBytes(20)
        val method = methodRepository.save(MfaMethod(subjectId, MfaMethodType.TOTP, secretStore.store(secret), clock.instant()))
        val base32 = Base32.encode(secret)
        val label = URLEncoder.encode("$ISSUER:$accountLabel", Charsets.UTF_8)
        return TotpEnrollment(method.requireId(), base32, "otpauth://totp/$label?secret=$base32&issuer=$ISSUER")
    }

    fun confirmTotp(subjectId: Long, methodId: Long, code: String) {
        val method = methodRepository.findByIdOrNull(methodId)?.takeIf { it.subjectId == subjectId }
            ?: throw NotFoundException("MFA 수단", methodId)
        if (!consume(method, code)) throw BusinessRuleException("인증 코드가 맞지 않습니다")
        method.confirm()
    }

    /** 이 사람의 MFA 수단을 트랜잭션이 끝날 때까지 잠근다. 같은 사람에 대한 시도를 줄 세워, 횟수를 세고 기록하는 사이에 다른 시도가 끼지 못하게 한다 */
    fun lock(subjectId: Long) {
        methodRepository.findBySubjectIdForUpdate(subjectId)
    }

    /** 확인을 마친 TOTP 중 하나라도 코드가 맞고, 그 코드를 처음 쓰는 것이면 통과 */
    fun verify(subjectId: Long, code: String): Boolean =
        methodRepository.findBySubjectIdForUpdate(subjectId)
            .filter { it.isVerified && it.methodType == MfaMethodType.TOTP }
            .any { consume(it, code) }

    @Transactional(readOnly = true)
    fun hasVerifiedMethod(subjectId: Long): Boolean = verifiedMethods(subjectId).isNotEmpty()

    /** 확인을 마친 TOTP 수단. 본인 화면의 등록 목록 */
    @Transactional(readOnly = true)
    fun verifiedMethods(subjectId: Long): List<MfaMethod> =
        methodRepository.findBySubjectId(subjectId).filter { it.isVerified && it.methodType == MfaMethodType.TOTP }.sortedBy { it.registeredAt }

    fun remove(subjectId: Long, methodId: Long) {
        val method = methodRepository.findByIdOrNull(methodId)?.takeIf { it.subjectId == subjectId }
            ?: throw NotFoundException("MFA 수단", methodId)
        delete(method)
    }

    /**
     * 관리자 초기화 (기기 분실 등). 지운 수단을 감사 기록으로 남긴다. 로그인 세션은 그대로 둔다:
     * 이미 로그인한 세션은 그 수단이 아니어도 유효하고, 끊을지는 관리자가 따로 정한다
     */
    fun removeByAdmin(subjectId: Long, methodId: Long) {
        val method = methodRepository.findByIdOrNull(methodId)?.takeIf { it.subjectId == subjectId }
            ?: throw NotFoundException("MFA 수단", methodId)
        val removed = mapOf("methodId" to methodId, "methodType" to method.methodType.name, "registeredAt" to method.registeredAt)
        delete(method)
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "MFA_RESET", removed, null))
    }

    private fun delete(method: MfaMethod) {
        method.secretReference?.let(secretStore::delete)
        methodRepository.delete(method)
    }


    private fun consume(method: MfaMethod, code: String): Boolean {
        val reference = method.secretReference ?: return false
        val step = Totp.matchingStep(secretStore.load(reference), code, clock.instant()) ?: return false
        return method.use(step)
    }

    companion object {
        const val ISSUER = "DIDRAKON"
    }
}
