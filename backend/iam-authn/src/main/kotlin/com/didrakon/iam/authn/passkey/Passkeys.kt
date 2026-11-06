package com.didrakon.iam.authn.passkey

import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.event.PasskeyChangedEvent
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.data.repository.findByIdOrNull
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.authentication.AccountStatusException
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria
import org.springframework.security.web.webauthn.api.Bytes
import org.springframework.security.web.webauthn.api.CredentialRecord
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement
import org.springframework.security.web.webauthn.api.UserVerificationRequirement
import org.springframework.security.web.webauthn.management.JdbcPublicKeyCredentialUserEntityRepository
import org.springframework.security.web.webauthn.management.JdbcUserCredentialRepository
import org.springframework.security.web.webauthn.management.PublicKeyCredentialCreationOptionsRequest
import org.springframework.security.web.webauthn.management.PublicKeyCredentialUserEntityRepository
import org.springframework.security.web.webauthn.management.UserCredentialRepository
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations
import org.springframework.security.web.webauthn.management.Webauthn4JRelyingPartyOperations
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

/**
 * 패스키(WebAuthn) 저장소와 신뢰 당사자 설정. Spring Security 의 /webauthn/… · /login/webauthn 필터가 이 빈을 쓴다.
 * - WebAuthn 사용자 이름(user_entities.name)은 **subject ID** 다. 로그인 결과 principal 이름이 그대로 토큰 sub 가 된다.
 * - 사용자 확인(생체·PIN)을 필수로 요구한다. 그래야 기기 소지 + 사용자 확인으로 MFA 가 된다.
 */
@Configuration
class PasskeyConfig(private val properties: AuthnProperties) {
    @Bean
    fun publicKeyCredentialUserEntityRepository(jdbcTemplate: JdbcTemplate): PublicKeyCredentialUserEntityRepository =
        JdbcPublicKeyCredentialUserEntityRepository(jdbcTemplate)

    @Bean
    fun userCredentialRepository(
        jdbcTemplate: JdbcTemplate,
        userEntities: PublicKeyCredentialUserEntityRepository,
        eventPublisher: ApplicationEventPublisher,
    ): UserCredentialRepository = AuditedUserCredentialRepository(JdbcUserCredentialRepository(jdbcTemplate), userEntities, eventPublisher)

    @Bean
    fun webAuthnRelyingPartyOperations(
        userEntities: PublicKeyCredentialUserEntityRepository,
        userCredentials: UserCredentialRepository,
        accountService: LocalAccountService,
    ): WebAuthnRelyingPartyOperations {
        val rp = PublicKeyCredentialRpEntity.builder().id(properties.webauthnRpId()).name(RP_NAME).build()
        val operations = Webauthn4JRelyingPartyOperations(userEntities, userCredentials, rp, properties.webauthnAllowedOrigins()).apply {
            setCustomizeCreationOptions {
                it.authenticatorSelection(
                    AuthenticatorSelectionCriteria.builder()
                        .userVerification(UserVerificationRequirement.REQUIRED)
                        .residentKey(ResidentKeyRequirement.REQUIRED)
                        .build(),
                )
            }
            setCustomizeRequestOptions { it.userVerification(UserVerificationRequirement.REQUIRED) }
        }
        return PasskeyRelyingPartyOperations(operations, accountService)
    }

    companion object {
        const val RP_NAME = "DIDRAKON IAM"
    }
}

/**
 * 등록은 LOCAL 계정만 한다. 인증기(브라우저·휴대폰)에 보이는 계정 이름은 subject ID 대신 로그인 ID 로 바꿔 보낸다
 * (저장되는 WebAuthn 사용자 이름은 그대로 subject ID 다. 등록 검증은 사용자 핸들(id)만 쓴다)
 */
class PasskeyRelyingPartyOperations(
    private val delegate: WebAuthnRelyingPartyOperations,
    private val accountService: LocalAccountService,
) : WebAuthnRelyingPartyOperations by delegate {
    override fun createPublicKeyCredentialCreationOptions(request: PublicKeyCredentialCreationOptionsRequest): PublicKeyCredentialCreationOptions {
        val identity = request.authentication.name.toLongOrNull()?.let(accountService::findLocalIdentity)
            ?: throw IllegalArgumentException("LOCAL 계정만 패스키를 등록할 수 있습니다")
        val options = delegate.createPublicKeyCredentialCreationOptions(request)
        val shown = ImmutablePublicKeyCredentialUserEntity.builder()
            .id(options.user.id)
            .name(identity.externalId)
            .displayName(identity.externalId)
            .build()
        return PublicKeyCredentialCreationOptions.builder()
            .rp(options.rp)
            .user(shown)
            .challenge(options.challenge)
            .pubKeyCredParams(options.pubKeyCredParams)
            .timeout(options.timeout)
            .excludeCredentials(options.excludeCredentials)
            .authenticatorSelection(options.authenticatorSelection)
            .attestation(options.attestation)
            .extensions(options.extensions)
            .build()
    }
}

/** 새 패스키 저장과 삭제를 이벤트로 알린다 (감사 기록). 로그인할 때의 서명 횟수·마지막 사용 갱신은 알리지 않는다 */
class AuditedUserCredentialRepository(
    private val delegate: UserCredentialRepository,
    private val userEntities: PublicKeyCredentialUserEntityRepository,
    private val eventPublisher: ApplicationEventPublisher,
) : UserCredentialRepository by delegate {
    override fun save(credentialRecord: CredentialRecord) {
        val added = delegate.findByCredentialId(credentialRecord.credentialId) == null
        delegate.save(credentialRecord)
        if (added) publish(credentialRecord, added = true)
    }

    override fun delete(credentialId: Bytes) {
        val record = delegate.findByCredentialId(credentialId) ?: return
        delegate.delete(credentialId)
        publish(record, added = false)
    }

    private fun publish(record: CredentialRecord, added: Boolean) {
        val subjectId = userEntities.findById(record.userEntityUserId)?.name?.toLongOrNull() ?: return
        eventPublisher.publishEvent(PasskeyChangedEvent(subjectId, record.credentialId.toBase64UrlString(), record.label, added))
    }
}

/** 패스키 로그인을 막는 계정 상태(사용 안 함·퇴사·잠금·일시 잠금). Spring 이 BadCredentialsException 으로 감싸므로 cause 로 꺼낸다 */
class PasskeyAccountUnavailableException(val subjectId: Long, state: String) :
    AccountStatusException("패스키로 로그인할 수 없는 계정 상태입니다: $state")

/**
 * 패스키 로그인의 계정 확인. WebAuthn 사용자 이름(subject ID)으로 LOCAL 계정을 찾는다.
 * Spring 의 WebAuthn 인증은 UserDetails 의 사용 가능 여부를 보지 않으므로 여기서 상태를 확인해 막는다.
 * 비밀번호·코드 실패로 생긴 일시 잠금도 막는다: 잠금은 "지금 이 계정에 공격이 있다"는 신호이고, 관리자 잠금 해제·
 * 셀프 해제·만료 전까지는 어떤 방법으로도 들어오지 못하게 한다 (비밀번호 로그인과 같은 규칙).
 * 비밀번호 인증 요소는 주지 않는다 (amr 에 pwd 가 들어가지 않게).
 */
@Component
@Transactional(readOnly = true)
class PasskeyAccounts(
    private val accountService: LocalAccountService,
    private val subjectRepository: SubjectRepository,
) {
    fun loadUser(name: String): UserDetails {
        val subjectId = name.toLongOrNull() ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        val identity = accountService.findLocalIdentity(subjectId) ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        val subject = subjectRepository.findByIdOrNull(subjectId) ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        if (subject.status != SubjectStatus.ACTIVE) throw PasskeyAccountUnavailableException(subjectId, subject.status.name)
        if (accountService.isTemporarilyLocked(identity.requireId())) throw PasskeyAccountUnavailableException(subjectId, "TEMPORARILY_LOCKED")
        return User.withUsername(name).password("").authorities(emptyList()).build()
    }
}

/** 등록한 패스키. 공개키 등 인증 자료는 주지 않는다 */
data class Passkey(val credentialId: String, val label: String, val createdAt: Instant?, val lastUsedAt: Instant?)

/** 본인 패스키 목록과 삭제. 등록은 Spring 의 /webauthn/register 가 한다 */
@Service
class PasskeyService(
    private val userEntities: PublicKeyCredentialUserEntityRepository,
    private val userCredentials: UserCredentialRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {
    fun list(subjectId: Long): List<Passkey> {
        val entity = userEntities.findByUsername(subjectId.toString()) ?: return emptyList()
        return userCredentials.findByUserId(entity.id)
            .map { Passkey(it.credentialId.toBase64UrlString(), it.label, it.created, it.lastUsed) }
            .sortedBy { it.createdAt }
    }

    /** 본인 것이 아니거나 없는 ID 는 구분하지 않고 NotFound */
    @Transactional
    fun remove(subjectId: Long, credentialId: String) {
        val entity = userEntities.findByUsername(subjectId.toString())
        val record = runCatching { Bytes.fromBase64(credentialId) }.getOrNull()
            ?.let(userCredentials::findByCredentialId)
            ?.takeIf { entity != null && it.userEntityUserId == entity.id }
            ?: throw NotFoundException("패스키", credentialId)
        userCredentials.delete(record.credentialId)
    }

    /** 관리자 초기화 (기기 분실 등). 패스키 삭제 기록에 더해 관리자가 지웠다는 감사 기록을 남긴다 */
    @Transactional
    fun removeByAdmin(subjectId: Long, credentialId: String) {
        val label = list(subjectId).firstOrNull { it.credentialId == credentialId }?.label
        remove(subjectId, credentialId)
        eventPublisher.publishEvent(
            AdminChangeEvent("USER", subjectId, "PASSKEY_RESET", mapOf("credentialId" to credentialId, "label" to label), null),
        )
    }
}
