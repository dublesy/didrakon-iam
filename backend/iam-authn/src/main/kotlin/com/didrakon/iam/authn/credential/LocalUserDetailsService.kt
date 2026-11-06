package com.didrakon.iam.authn.credential

import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.identity.provider.IdentityRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import org.springframework.data.repository.findByIdOrNull
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.core.userdetails.UsernameNotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

/**
 * 로그인 ID 로 LOCAL 계정을 찾는다. 인증 후 principal 이름은 로그인 ID 가 아니라 **subject ID** 다
 * (토큰 sub 와 권한 판정이 subject ID 를 쓴다). 표준 [User] 를 써야 SAS 가 authorization 에 직렬화할 수 있다.
 */
@Service
@Transactional(readOnly = true)
class LocalUserDetailsService(
    private val accountService: LocalAccountService,
    private val identityRepository: IdentityRepository,
    private val subjectRepository: SubjectRepository,
    private val clock: Clock,
) : UserDetailsService {
    override fun loadUserByUsername(loginId: String): UserDetails {
        val credential = accountService.findCredential(loginId) ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        val identity = identityRepository.findByIdOrNull(credential.identityId) ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        val subject = subjectRepository.findByIdOrNull(identity.subjectId) ?: throw UsernameNotFoundException("계정을 찾을 수 없습니다")
        val now = clock.instant()

        return User.withUsername(subject.requireId().toString())
            .password(credential.passwordHash)
            .authorities(AuthFactors.PASSWORD)
            .disabled(subject.status == SubjectStatus.DISABLED || subject.status == SubjectStatus.RETIRED)
            .accountLocked(subject.status == SubjectStatus.LOCKED || credential.isLockedAt(now))
            // 비밀번호를 확인한 뒤에야 검사되므로, 이 예외가 나면 비밀번호는 맞은 것이다 (LoginFailureHandler 가 변경 화면으로 보낸다)
            .credentialsExpired(credential.needsChangeAt(now))
            .build()
    }
}
