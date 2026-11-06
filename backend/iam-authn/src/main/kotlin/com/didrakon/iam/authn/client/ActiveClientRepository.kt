package com.didrakon.iam.authn.client

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository

/**
 * 사용 안 함으로 바꾼 SSO 클라이언트는 client_id 로 찾을 수 없게 한다. 그래서 authorize·token 요청이 "없는 클라이언트"로 거부된다.
 * ID 조회(findById)는 그대로 둔다. 이미 저장된 인가 기록을 읽을 때 쓰이며, 막으면 토큰 조회가 서버 오류가 된다.
 * 이미 발급된 토큰은 만료될 때까지 남으므로, 즉시 끊으려면 세션·토큰을 따로 폐기한다.
 */
class ActiveClientRepository(
    private val delegate: RegisteredClientRepository,
    private val ssoClientRepository: SsoClientRepository,
) : RegisteredClientRepository by delegate {
    override fun findByClientId(clientId: String): RegisteredClient? {
        if (ssoClientRepository.findByClientCode(clientId)?.isActive == false) return null
        return delegate.findByClientId(clientId)
    }
}
