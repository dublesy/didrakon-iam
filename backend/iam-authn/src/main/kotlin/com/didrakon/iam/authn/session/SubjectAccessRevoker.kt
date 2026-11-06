package com.didrakon.iam.authn.session

import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.credential.PasswordChangedEvent
import com.didrakon.iam.identity.event.SubjectStatusChangedEvent
import com.didrakon.iam.identity.subject.SubjectStatus
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/**
 * 사용 안 함·잠김·퇴사가 되면 로그인 세션, 발급한 토큰, API 키를 바로 회수한다.
 * 비밀번호가 바뀌면 로그인 세션과 토큰을 끝낸다 (훔친 세션·refresh token 이 남지 않게). API 키는 비밀번호와 따로 관리하므로 두고, 필요하면 폐기한다
 */
@Component
class SubjectAccessRevoker(
    private val sessionService: LoginSessionService,
    private val apiKeyService: ApiKeyService,
) {
    @EventListener
    fun onStatusChanged(event: SubjectStatusChangedEvent) {
        if (event.status == SubjectStatus.ACTIVE) return
        sessionService.revokeAll(event.subjectId)
        apiKeyService.revokeAll(event.subjectId)
    }

    @EventListener
    fun onPasswordChanged(event: PasswordChangedEvent) {
        sessionService.revokeAll(event.subjectId)
    }
}
