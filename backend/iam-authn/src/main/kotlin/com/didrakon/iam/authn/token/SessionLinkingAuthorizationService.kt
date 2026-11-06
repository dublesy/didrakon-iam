package com.didrakon.iam.authn.token

import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.session.LoginSessionRepository
import com.didrakon.iam.common.crypto.sha256Hex
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.web.context.request.RequestContextHolder
import org.springframework.web.context.request.ServletRequestAttributes

/**
 * 인가 기록을 저장할 때, 브라우저 요청(authorize)이면 그 브라우저의 로그인 세션과 연결해 둔다.
 * 토큰 교환·갱신 요청에는 브라우저 세션이 없지만 같은 인가 ID 를 쓰므로 authorize 때의 연결이 그대로 쓰인다.
 * 그래서 로그인 세션을 끊거나 로그아웃하면 그 세션에서 나온 토큰을 함께 회수할 수 있다 ([TokenRevoker]).
 */
class SessionLinkingAuthorizationService(
    private val delegate: OAuth2AuthorizationService,
    private val sessionRepository: LoginSessionRepository,
    private val tokenRevoker: TokenRevoker,
) : OAuth2AuthorizationService by delegate {
    override fun save(authorization: OAuth2Authorization) {
        delegate.save(authorization)
        val request = (RequestContextHolder.getRequestAttributes() as? ServletRequestAttributes)?.request ?: return
        val sessionKey = request.getSession(false)?.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String ?: return
        val session = sessionRepository.findBySessionKeyHash(sha256Hex(sessionKey)) ?: return
        tokenRevoker.link(authorization.id, session.requireId(), session.subjectId)
    }
}
