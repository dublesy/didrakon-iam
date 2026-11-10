package com.didrakon.iam.authn.token

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2TokenIntrospectionAuthenticationToken

/**
 * 토큰 검사(introspection)는 그 토큰을 받은 클라이언트만 한다. 다른 클라이언트의 토큰은 비활성으로 답한다.
 * 기본 SAS 는 인증한 클라이언트면 누구의 토큰이든 사용자·scope 를 알려 주므로, 연동 시스템 하나가 다른 시스템의 토큰을 들여다볼 수 있다.
 * 다른 시스템의 사용자 토큰(JWT)을 검증해야 하면 JWKS 로 서명을 확인한다
 */
class OwnTokenIntrospection(private val delegate: AuthenticationProvider) : AuthenticationProvider by delegate {
    override fun authenticate(authentication: Authentication): Authentication? {
        val result = delegate.authenticate(authentication)
        if (result !is OAuth2TokenIntrospectionAuthenticationToken || !result.tokenClaims.isActive) return result
        val caller = result.principal as? OAuth2ClientAuthenticationToken ?: return result
        if (result.tokenClaims.clientId == caller.registeredClient?.clientId) return result
        return OAuth2TokenIntrospectionAuthenticationToken(result.token, caller, OAuth2TokenIntrospection.builder().build())
    }
}
