package com.didrakon.iam.authn.token

import com.didrakon.iam.common.crypto.sha256Hex
import org.springframework.security.oauth2.core.OAuth2AccessToken
import org.springframework.security.oauth2.core.OAuth2DeviceCode
import org.springframework.security.oauth2.core.OAuth2RefreshToken
import org.springframework.security.oauth2.core.OAuth2Token
import org.springframework.security.oauth2.core.OAuth2UserCode
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.core.oidc.OidcIdToken
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType
import java.time.Instant

/**
 * code·token 값을 SHA-256 hash 로만 저장한다 (ERD 결정 사항 3). 실제 저장은 [delegate](JDBC) 가 한다.
 *
 * SAS 는 읽은 authorization 을 고쳐 다시 저장하므로 "이미 hash 인 값"과 "새 원문"을 구분해야 한다.
 * - 읽을 때: 저장된 hash 는 [HASHED_PREFIX] 를 붙여 돌려준다. 단, 조회에 쓴 토큰은 원문으로 되돌려
 *   폐기·검사(introspection) 엔드포인트의 `getToken(원문)` 이 동작하게 한다.
 * - 저장할 때: [HASHED_PREFIX] 가 붙은 값은 떼기만 하고, 원문은 hash 한다.
 * 저장된 값을 클라이언트에 다시 줄 수 없으므로 refresh token 재사용(reuseRefreshTokens)은 쓰지 않는다.
 */
class HashingOAuth2AuthorizationService(
    private val delegate: OAuth2AuthorizationService,
) : OAuth2AuthorizationService {
    override fun save(authorization: OAuth2Authorization) = delegate.save(transform(authorization) { it.toStored() })

    override fun remove(authorization: OAuth2Authorization) = delegate.remove(authorization)

    override fun findById(id: String): OAuth2Authorization? =
        delegate.findById(id)?.let { loaded -> transform(loaded) { HASHED_PREFIX + it } }

    override fun findByToken(token: String, tokenType: OAuth2TokenType?): OAuth2Authorization? {
        // state 는 토큰이 아니라 짧게 쓰는 무작위 값이라 원문 그대로 저장·조회한다
        if (tokenType?.value == OAuth2ParameterNames.STATE) return delegate.findByToken(token, tokenType)

        val hashed = sha256Hex(token)
        val loaded = delegate.findByToken(hashed, tokenType) ?: return null
        return transform(loaded) { stored -> if (stored == hashed) token else HASHED_PREFIX + stored }
    }

    private fun String.toStored(): String = if (startsWith(HASHED_PREFIX)) removePrefix(HASHED_PREFIX) else sha256Hex(this)

    /** authorization 안의 모든 code·token 값을 [convert] 로 바꾼 사본. 메타데이터(만료·무효화 여부, claims)는 그대로 둔다 */
    private fun transform(authorization: OAuth2Authorization, convert: (String) -> String): OAuth2Authorization {
        val builder = OAuth2Authorization.from(authorization)
        TOKEN_TYPES.forEach { type ->
            authorization.getToken(type)?.let { holder ->
                builder.token(copy(holder.token, convert(holder.token.tokenValue))) { it.putAll(holder.metadata) }
            }
        }
        return builder.build()
    }

    private fun copy(token: OAuth2Token, value: String): OAuth2Token = when (token) {
        is OAuth2AuthorizationCode -> OAuth2AuthorizationCode(value, token.issuedAt.required(), token.expiresAt.required())
        is OAuth2AccessToken -> OAuth2AccessToken(token.tokenType, value, token.issuedAt, token.expiresAt, token.scopes)
        is OAuth2RefreshToken -> OAuth2RefreshToken(value, token.issuedAt, token.expiresAt)
        is OidcIdToken -> OidcIdToken(value, token.issuedAt.required(), token.expiresAt.required(), token.claims)
        is OAuth2UserCode -> OAuth2UserCode(value, token.issuedAt.required(), token.expiresAt.required())
        is OAuth2DeviceCode -> OAuth2DeviceCode(value, token.issuedAt.required(), token.expiresAt.required())
        else -> throw IllegalStateException("hash 저장을 지원하지 않는 토큰 종류입니다: ${token.javaClass.name}")
    }

    /** SAS 가 이 토큰들은 항상 발급·만료 시각을 넣는다 */
    private fun Instant?.required(): Instant = this ?: throw IllegalStateException("토큰에 발급·만료 시각이 없습니다")

    companion object {
        /** 값이 이미 hash 라는 표시. 원문 토큰(base64url, JWT, user code)에는 ':' 가 없어 겹치지 않는다 */
        const val HASHED_PREFIX = "hash:"

        private val TOKEN_TYPES = listOf(
            OAuth2AuthorizationCode::class.java,
            OAuth2AccessToken::class.java,
            OAuth2RefreshToken::class.java,
            OidcIdToken::class.java,
            OAuth2UserCode::class.java,
            OAuth2DeviceCode::class.java,
        )
    }
}
