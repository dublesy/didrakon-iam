package com.didrakon.iam.authn.credential

import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.provider.Identity
import com.didrakon.iam.identity.provider.IdentityProviderRepository
import com.didrakon.iam.identity.provider.IdentityRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Propagation
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

/** 비밀번호가 바뀌었다 (본인 변경·셀프 재설정·만료 변경·관리자 초기화). 그 사람의 로그인 세션과 토큰을 끝내는 데 쓴다 */
data class PasswordChangedEvent(val subjectId: Long)

/** LOCAL IdP 계정(로그인 ID + 비밀번호) 관리 */
@Service
@Transactional
class LocalAccountService(
    private val identityProviderRepository: IdentityProviderRepository,
    private val identityRepository: IdentityRepository,
    private val credentialRepository: LocalCredentialRepository,
    private val subjectRepository: SubjectRepository,
    private val passwordEncoder: PasswordEncoder,
    private val properties: AuthnProperties,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    fun createAccount(subjectId: Long, loginId: String, rawPassword: String): Identity {
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        val providerId = localProviderId()
        if (identityRepository.findByProviderIdAndExternalId(providerId, loginId) != null) {
            throw BusinessRuleException("이미 사용 중인 로그인 ID 입니다: $loginId")
        }
        validatePassword(loginId, rawPassword)

        val identity = identityRepository.save(Identity(subjectId, providerId, externalId = loginId, loginId = loginId, isPrimary = true))
        val now = clock.instant()
        credentialRepository.save(
            LocalCredential(identity.requireId(), encode(rawPassword), now, properties.passwordMaxAge?.let(now::plus)),
        )
        return identity
    }

    /**
     * 로그인 계정이 없는 기존 사용자에게 관리자가 LOCAL 계정을 만들어 준다.
     * 관리자가 정한 첫 비밀번호는 다음 로그인에서 본인이 바꿔야 한다 (관리자가 계속 알지 않도록)
     */
    fun createAccountByAdmin(subjectId: Long, loginId: String, rawPassword: String): Identity {
        if (findLocalIdentity(subjectId) != null) throw BusinessRuleException("이미 로그인 계정이 있습니다")
        val identity = createAccount(subjectId, loginId, rawPassword)
        credentialRepository.findByIdOrNull(identity.requireId())?.requirePasswordChange()
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "CREATE_LOGIN_ACCOUNT", null, mapOf("loginId" to loginId)))
        return identity
    }

    /**
     * 실패 횟수와 잠금도 풀린다. [requireChangeOnNextLogin] 이면 다음 로그인에서 본인이 바꿔야 한다 (관리자 초기화).
     * 지금 비밀번호와 같은 값으로는 바꿀 수 없다
     */
    fun changePassword(identityId: Long, rawPassword: String, requireChangeOnNextLogin: Boolean = false) {
        val credential = credentialRepository.findByIdOrNull(identityId) ?: throw NotFoundException("로컬 계정", identityId)
        val identity = identityRepository.findByIdOrNull(identityId) ?: throw NotFoundException("계정", identityId)
        validatePassword(identity.externalId, rawPassword)
        if (passwordEncoder.matches(rawPassword, credential.passwordHash)) throw BusinessRuleException("지금 비밀번호와 다른 값을 쓰세요")
        val now = clock.instant()
        credential.changePassword(encode(rawPassword), now, properties.passwordMaxAge?.let(now::plus), requireChangeOnNextLogin)
        eventPublisher.publishEvent(PasswordChangedEvent(identity.subjectId))
    }

    /** 로그인한 본인의 변경. 현재 비밀번호가 틀리면 로그인 실패와 같이 세어 잠금에 쓴다 */
    @Transactional(noRollbackFor = [BusinessRuleException::class])
    fun changeOwnPassword(subjectId: Long, currentPassword: String, newPassword: String) {
        val identity = findLocalIdentity(subjectId) ?: throw NotFoundException("로컬 계정", subjectId)
        val credential = credentialRepository.findByIdOrNull(identity.requireId()) ?: throw NotFoundException("로컬 계정", subjectId)
        if (!passwordEncoder.matches(currentPassword, credential.passwordHash)) {
            credential.recordFailure(clock.instant(), properties.maxFailedAttempts, properties.lockDuration)
            throw BusinessRuleException("현재 비밀번호가 맞지 않습니다")
        }
        changePassword(identity.requireId(), newPassword)
    }

    /**
     * 로그인 실패를 기록한다. 인증 실패로 로그인 요청이 끝나도 기록은 남아야 하므로 별도 트랜잭션으로 커밋한다.
     * 없는 로그인 ID 는 무시한다 (계정 존재 여부를 드러내지 않는다).
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun recordFailure(loginId: String) {
        findCredential(loginId)?.recordFailure(clock.instant(), properties.maxFailedAttempts, properties.lockDuration)
    }

    /**
     * MFA 코드 실패도 비밀번호 실패와 같은 횟수로 센다 (비밀번호를 통과한 뒤의 코드 추측 차단).
     * 이번 실패로 잠겼으면 true. 실패 기록은 남아야 하므로 별도 트랜잭션으로 커밋한다
     */
    @Transactional(propagation = Propagation.REQUIRES_NEW)
    fun recordMfaFailure(subjectId: Long): Boolean {
        val identity = findLocalIdentity(subjectId) ?: return false
        val credential = credentialRepository.findByIdOrNull(identity.requireId()) ?: return false
        val now = clock.instant()
        credential.recordFailure(now, properties.maxFailedAttempts, properties.lockDuration)
        return credential.isLockedAt(now)
    }

    /** 비밀번호·코드 실패로 지금 일시 잠겨 있는지 */
    @Transactional(readOnly = true)
    fun isTemporarilyLocked(identityId: Long): Boolean =
        credentialRepository.findByIdOrNull(identityId)?.isLockedAt(clock.instant()) ?: false

    /** 이번 성공 직전까지 이어진 실패 횟수. [recordSuccess] 전에 읽어야 한다 */
    @Transactional(readOnly = true)
    fun consecutiveFailures(identityId: Long): Int = credentialRepository.findByIdOrNull(identityId)?.failedAttemptCount ?: 0

    fun recordSuccess(identityId: Long) {
        credentialRepository.findByIdOrNull(identityId)?.recordSuccess()
    }

    /** 관리자 잠금 해제. 비밀번호는 그대로 두고 실패 횟수와 잠금만 푼다 */
    fun unlock(subjectId: Long) {
        val identity = findLocalIdentity(subjectId) ?: throw NotFoundException("로컬 계정", subjectId)
        val credential = credentialRepository.findByIdOrNull(identity.requireId()) ?: throw NotFoundException("로컬 계정", subjectId)
        val before = lockSnapshot(credential)
        credential.recordSuccess()
        eventPublisher.publishEvent(AdminChangeEvent("USER", subjectId, "UNLOCK", before, lockSnapshot(credential)))
    }

    /** subject 의 LOCAL 비밀번호 상태 (관리 화면 표시용). LOCAL 계정이 없으면 null */
    @Transactional(readOnly = true)
    fun findLocalCredential(subjectId: Long): LocalCredential? =
        findLocalIdentity(subjectId)?.let { credentialRepository.findByIdOrNull(it.requireId()) }

    private fun lockSnapshot(credential: LocalCredential) =
        mapOf("failedAttemptCount" to credential.failedAttemptCount, "lockedUntil" to credential.lockedUntil)

    /** 로그인한 subject 의 LOCAL 계정 */
    @Transactional(readOnly = true)
    fun findLocalIdentity(subjectId: Long): Identity? {
        val providerId = localProviderId()
        return identityRepository.findBySubjectId(subjectId).firstOrNull { it.providerId == providerId }
    }

    @Transactional(readOnly = true)
    fun findIdentity(loginId: String): Identity? = identityRepository.findByProviderIdAndExternalId(localProviderId(), loginId)

    @Transactional(readOnly = true)
    fun findCredential(loginId: String): LocalCredential? =
        findIdentity(loginId)?.let { credentialRepository.findByIdOrNull(it.requireId()) }

    private fun encode(rawPassword: String): String =
        passwordEncoder.encode(rawPassword) ?: throw IllegalStateException("비밀번호 인코딩 실패")

    private fun validatePassword(loginId: String, rawPassword: String) {
        if (rawPassword.length < properties.passwordMinLength) {
            throw BusinessRuleException("비밀번호는 ${properties.passwordMinLength}자 이상이어야 합니다")
        }
        if (rawPassword.contains(loginId, ignoreCase = true)) throw BusinessRuleException("비밀번호에 로그인 ID 를 넣을 수 없습니다")
    }

    private fun localProviderId(): Long =
        identityProviderRepository.findByProviderCode(LOCAL_PROVIDER_CODE)?.requireId()
            ?: throw IllegalStateException("LOCAL IdP 행이 없습니다 (V7 마이그레이션 확인)")

    companion object {
        const val LOCAL_PROVIDER_CODE = "LOCAL"
    }
}
