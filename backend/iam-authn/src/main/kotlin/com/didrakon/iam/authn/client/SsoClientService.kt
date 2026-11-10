package com.didrakon.iam.authn.client

import org.springframework.data.repository.findByIdOrNull
import com.didrakon.iam.authn.token.TokenRevoker
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.crypto.randomUrlSafe
import com.didrakon.iam.common.error.BusinessRuleException
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.core.oidc.OidcScopes
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Duration
import java.util.UUID

data class ClientRegistration(
    val clientCode: String,
    val clientName: String,
    val clientType: ClientType,
    /** WEB·MOBILE 만 */
    val redirectUris: Set<String> = emptySet(),
    val postLogoutRedirectUris: Set<String> = emptySet(),
    /** openid·profile 외에 요청할 수 있는 scope */
    val scopes: Set<String> = emptySet(),
    /** false 면 비밀값 없는 public client (PKCE 필수) */
    val confidential: Boolean = true,
    val requireMfa: Boolean = false,
    /** OIDC Back-Channel Logout 수신 주소 (WEB·MOBILE 만 의미가 있다) */
    val backchannelLogoutUri: String? = null,
    /** 토큰에 role = "authenticated" 를 넣는다 (Supabase Third-Party Auth) */
    val supabaseRoleClaim: Boolean = false,
    /** 앱 런처 시작 주소 (WEB·MOBILE). 있으면 IAM 홈의 내 앱 목록에 나온다 */
    val homeUrl: String? = null,
)

/** 등록 결과. 비밀값 원문은 이때 한 번만 돌려준다 */
data class RegisteredClientResult(val ssoClient: SsoClient, val clientId: String, val clientSecret: String?)

/** SAS 에 등록된 로그인 설정. scopes 에는 openid·profile 도 들어 있다 */
data class ClientLoginSettings(
    val redirectUris: List<String>,
    val postLogoutRedirectUris: List<String>,
    val scopes: List<String>,
    /** 비밀값이 있는 클라이언트 (client_secret_basic) */
    val confidential: Boolean,
)

/** 로그인 설정 변경. null 인 항목은 그대로 둔다. scopes 는 openid·profile 외의 것만 적어도 된다 (사용자 로그인 클라이언트는 둘을 늘 넣는다) */
data class ClientLoginChange(
    val redirectUris: Set<String>? = null,
    val postLogoutRedirectUris: Set<String>? = null,
    val scopes: Set<String>? = null,
)

@Service
@Transactional
class SsoClientService(
    private val registeredClientRepository: RegisteredClientRepository,
    private val ssoClientRepository: SsoClientRepository,
    private val passwordEncoder: PasswordEncoder,
    private val tokenRevoker: TokenRevoker,
    private val eventPublisher: ApplicationEventPublisher,
) {
    @Transactional(readOnly = true)
    fun clients(): List<SsoClient> = ssoClientRepository.findAll().sortedBy { it.clientCode }

    /** 목록 화면용: 클라이언트와 SAS 에 등록된 로그인 설정 */
    @Transactional(readOnly = true)
    fun clientsWithSettings(): List<Pair<SsoClient, ClientLoginSettings>> = clients().map { it to loginSettings(registered(it)) }

    /**
     * 이름, MFA 필수 여부, back-channel 로그아웃 주소, Supabase 호환 여부, 앱 런처 주소와 로그인 설정(redirect URI·로그아웃 후 주소·scope)을 바꾼다.
     * 클라이언트 코드(client_id)·유형·비밀값 유무는 바꾸지 않는다. SAS 등록 정보를 같은 ID 로 고쳐 저장하므로 client_id 는 그대로다.
     *
     * [protectedClientCode](관리 콘솔 iam-admin)의 로그인 설정은 바꿀 수 없다. 기동 시 초기 구성은 없을 때만 등록하고 다시 맞추지 않으므로
     * 저장된 값이 곧 콘솔이 로그인하는 주소다. 잘못 고치면 모든 관리자가 콘솔에 로그인하지 못해 화면으로 되돌릴 수 없다.
     */
    fun update(
        ssoClientId: Long,
        clientName: String,
        requireMfa: Boolean,
        backchannelLogoutUri: String?,
        supabaseRoleClaim: Boolean = false,
        homeUrl: String? = null,
        loginChange: ClientLoginChange = ClientLoginChange(),
        protectedClientCode: String? = null,
    ): SsoClient {
        val client = find(ssoClientId)
        if (clientName.isBlank()) throw BusinessRuleException("클라이언트 이름이 필요합니다")
        val registered = registered(client)
        val before = snapshot(client) + settingsSnapshot(registered)
        val changed = changedRegistration(client, registered, loginChange)
        if (changed != null) {
            if (client.clientCode == protectedClientCode) throw BusinessRuleException("관리 콘솔 클라이언트의 로그인 설정은 바꿀 수 없습니다")
            registeredClientRepository.save(changed)
        }
        client.update(clientName.trim(), requireMfa, validLogoutUri(backchannelLogoutUri), supabaseRoleClaim, validHomeUrl(homeUrl))
        eventPublisher.publishEvent(AdminChangeEvent("CLIENT", ssoClientId, "UPDATE", before, snapshot(client) + settingsSnapshot(changed ?: registered)))
        return client
    }

    /**
     * 비밀값을 새로 만든다. 원문은 이때 한 번만 돌려준다. 이전 비밀값은 바로 쓸 수 없고, 이미 발급된 토큰은 만료될 때까지 그대로다.
     * 비밀값 없는 public client 는 거부한다
     */
    fun rotateSecret(ssoClientId: Long): String {
        val client = find(ssoClientId)
        val registered = registered(client)
        if (!loginSettings(registered).confidential) throw BusinessRuleException("비밀값이 없는 클라이언트입니다 (public client)")
        val secret = randomUrlSafe(32)
        registeredClientRepository.save(
            RegisteredClient.from(registered)
                .clientSecret(passwordEncoder.encode(secret) ?: throw IllegalStateException("비밀값 인코딩 실패"))
                .build(),
        )
        // 비밀값은 감사 기록에 남기지 않는다
        eventPublisher.publishEvent(AdminChangeEvent("CLIENT", ssoClientId, "ROTATE_SECRET", null, mapOf("clientCode" to client.clientCode)))
        return secret
    }

    /**
     * 끄면 그 클라이언트로는 로그인·토큰 발급이 막히고([ActiveClientRepository]), 이미 발급한 토큰도 회수한다
     * (refresh·토큰 검사·userinfo 가 더는 통하지 않게). 관리 콘솔 자신은 끌 수 없다
     */
    fun changeActive(ssoClientId: Long, active: Boolean, protectedClientCode: String): SsoClient {
        val client = find(ssoClientId)
        if (client.isActive == active) return client
        if (!active && client.clientCode == protectedClientCode) throw BusinessRuleException("관리 콘솔 클라이언트는 끌 수 없습니다")
        val before = snapshot(client)
        client.changeActive(active)
        if (!active) tokenRevoker.revokeByClient(client.registeredClientId)
        eventPublisher.publishEvent(AdminChangeEvent("CLIENT", ssoClientId, if (active) "ACTIVATE" else "DEACTIVATE", before, snapshot(client)))
        return client
    }

    private fun find(id: Long): SsoClient = ssoClientRepository.findByIdOrNull(id) ?: throw NotFoundException("클라이언트", id)

    private fun registered(c: SsoClient): RegisteredClient =
        registeredClientRepository.findById(c.registeredClientId) ?: throw IllegalStateException("SAS 등록 정보가 없습니다: ${c.clientCode}")

    private fun loginSettings(r: RegisteredClient) =
        ClientLoginSettings(
            r.redirectUris.sorted(), r.postLogoutRedirectUris.sorted(), r.scopes.sorted(),
            confidential = ClientAuthenticationMethod.CLIENT_SECRET_BASIC in r.clientAuthenticationMethods,
        )

    private fun settingsSnapshot(r: RegisteredClient) =
        loginSettings(r).let { mapOf("redirectUris" to it.redirectUris, "postLogoutRedirectUris" to it.postLogoutRedirectUris, "scopes" to it.scopes) }

    /** 바뀐 것이 있으면 고친 등록 정보, 없으면 null */
    private fun changedRegistration(client: SsoClient, registered: RegisteredClient, change: ClientLoginChange): RegisteredClient? {
        val userFacing = client.clientType.userFacing()
        val redirectUris = change.redirectUris?.let { validRedirectUris(it, "redirect URI", client.clientType) } ?: registered.redirectUris
        val postLogout = change.postLogoutRedirectUris?.let { validRedirectUris(it, "로그아웃 후 주소", client.clientType) } ?: registered.postLogoutRedirectUris
        val scopes = change.scopes?.let { validScopes(it, userFacing) } ?: registered.scopes
        if (redirectUris == registered.redirectUris && postLogout == registered.postLogoutRedirectUris && scopes == registered.scopes) return null
        if (userFacing && redirectUris.isEmpty()) throw BusinessRuleException("사용자 로그인 클라이언트는 redirect URI 가 필요합니다")
        if (!userFacing && (redirectUris.isNotEmpty() || postLogout.isNotEmpty())) {
            throw BusinessRuleException("시스템 간 호출 클라이언트에는 로그인 주소를 둘 수 없습니다")
        }
        return RegisteredClient.from(registered)
            .redirectUris { it.clear(); it.addAll(redirectUris) }
            .postLogoutRedirectUris { it.clear(); it.addAll(postLogout) }
            .scopes { it.clear(); it.addAll(scopes) }
            .build()
    }

    private fun ClientType.userFacing() = this == ClientType.WEB || this == ClientType.MOBILE

    /**
     * 빈 줄은 버린다. 스킴이 있는 절대 주소만 받는다. fragment(#) 는 OAuth2 가 금지한다.
     * 웹 클라이언트는 http(s) 만, 모바일 앱은 사용자 정의 스킴도 받는다. 브라우저에서 스크립트·내용으로 해석되는 스킴(javascript: 등)은 막는다
     */
    private fun validRedirectUris(uris: Set<String>, label: String, clientType: ClientType): Set<String> =
        uris.map(String::trim).filter(String::isNotEmpty).onEach { value ->
            val parsed = runCatching { java.net.URI(value) }.getOrNull()
            if (parsed == null || !parsed.isAbsolute || parsed.fragment != null || (parsed.isOpaque && parsed.schemeSpecificPart.isNullOrBlank())) {
                throw BusinessRuleException("$label 는 절대 주소여야 하고 # 을 쓸 수 없습니다: $value")
            }
            val scheme = parsed.scheme.lowercase()
            if (scheme in BLOCKED_SCHEMES || (clientType == ClientType.WEB && scheme !in WEB_SCHEMES)) {
                throw BusinessRuleException("$label 에 쓸 수 없는 스킴입니다 (웹은 http·https 만): $value")
            }
        }.toSet()

    /** RFC 6749 scope-token 문자만. 사용자 로그인 클라이언트는 openid·profile 을 늘 넣는다 */
    private fun validScopes(scopes: Set<String>, userFacing: Boolean): Set<String> {
        val values = scopes.map(String::trim).filter(String::isNotEmpty).onEach { scope ->
            if (!scope.all { it.code in 0x21..0x7E && it != '"' && it != '\\' }) throw BusinessRuleException("scope 에 쓸 수 없는 문자가 있습니다: $scope")
        }.toSet()
        // iam. 으로 시작하는 scope 는 IAM 의 시스템 API(권한 판정·HR 연동)를 연다. 사용자 토큰에 들어가면 그 사람 대신 쓸 수 있으므로 시스템 클라이언트에만 준다
        if (userFacing) values.firstOrNull { it.startsWith(RESERVED_SCOPE_PREFIX) }?.let {
            throw BusinessRuleException("사용자 로그인 클라이언트에는 시스템 전용 scope 를 줄 수 없습니다: $it")
        }
        return if (userFacing) values + setOf(OidcScopes.OPENID, OidcScopes.PROFILE) else values
    }

    private fun snapshot(c: SsoClient) =
        mapOf(
            "clientName" to c.clientName, "requireMfa" to c.requireMfa, "backchannelLogoutUri" to c.backchannelLogoutUri,
            "supabaseRoleClaim" to c.supabaseRoleClaim, "homeUrl" to c.homeUrl, "isActive" to c.isActive,
        )

    /** 비우면 null. 절대 http(s) 주소만 받는다 */
    private fun validLogoutUri(uri: String?): String? {
        val value = uri?.trim()?.ifEmpty { null } ?: return null
        val parsed = runCatching { java.net.URI(value) }.getOrNull()
        if (parsed?.scheme !in setOf("http", "https") || parsed?.host.isNullOrBlank()) {
            throw BusinessRuleException("back-channel 로그아웃 주소는 http(s) 절대 주소여야 합니다")
        }
        return value
    }

    private fun validHomeUrl(url: String?): String? {
        val value = url?.trim()?.ifEmpty { null } ?: return null
        val parsed = runCatching { java.net.URI(value) }.getOrNull()
        if (parsed?.scheme !in setOf("http", "https") || parsed?.host.isNullOrBlank()) {
            throw BusinessRuleException("앱 시작 주소는 http(s) 절대 주소여야 합니다")
        }
        return value
    }

    fun register(request: ClientRegistration): RegisteredClientResult {
        if (ssoClientRepository.findByClientCode(request.clientCode) != null) {
            throw BusinessRuleException("이미 등록된 클라이언트 코드입니다: ${request.clientCode}")
        }
        // client credentials 토큰의 sub 는 클라이언트 코드다. 숫자뿐이면 같은 번호의 사용자(subject ID)와 헷갈린다
        if (request.clientCode.all(Char::isDigit)) throw BusinessRuleException("클라이언트 코드는 숫자만으로 만들 수 없습니다: ${request.clientCode}")
        val userFacing = request.clientType.userFacing()
        val redirectUris = if (userFacing) validRedirectUris(request.redirectUris, "redirect URI", request.clientType) else emptySet()
        val postLogoutRedirectUris = if (userFacing) validRedirectUris(request.postLogoutRedirectUris, "로그아웃 후 주소", request.clientType) else emptySet()
        val scopes = validScopes(request.scopes, userFacing)
        if (userFacing && redirectUris.isEmpty()) throw BusinessRuleException("사용자 로그인 클라이언트는 redirect URI 가 필요합니다")
        if (!userFacing && !request.confidential) throw BusinessRuleException("시스템 간 호출 클라이언트는 비밀값이 필요합니다")

        val secret = if (request.confidential) randomUrlSafe(32) else null
        val registered = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId(request.clientCode)
            .clientName(request.clientName)
            .apply {
                if (secret != null) {
                    clientSecret(passwordEncoder.encode(secret) ?: throw IllegalStateException("비밀값 인코딩 실패"))
                    clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                } else {
                    clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                }
                if (userFacing) {
                    authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    redirectUris.forEach(::redirectUri)
                    postLogoutRedirectUris.forEach(::postLogoutRedirectUri)
                } else {
                    authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                }
                scopes.forEach(::scope)
            }
            .clientSettings(
                ClientSettings.builder()
                    .requireAuthorizationConsent(false) // 사내 SSO 라 동의 화면을 띄우지 않는다
                    .requireProofKey(!request.confidential)
                    .build(),
            )
            .tokenSettings(
                TokenSettings.builder()
                    .accessTokenTimeToLive(Duration.ofMinutes(10))
                    .refreshTokenTimeToLive(Duration.ofHours(8))
                    // 토큰을 hash 로만 저장하므로 refresh token 은 매번 새로 발급한다 (ERD 결정 사항 3)
                    .reuseRefreshTokens(false)
                    .build(),
            )
            .build()
        registeredClientRepository.save(registered)

        val ssoClient = ssoClientRepository.save(
            SsoClient(registered.id, request.clientCode, request.clientName, request.clientType, request.requireMfa)
                .also {
                    it.update(
                        request.clientName, request.requireMfa, validLogoutUri(request.backchannelLogoutUri), request.supabaseRoleClaim,
                        validHomeUrl(request.homeUrl),
                    )
                },
        )
        return RegisteredClientResult(ssoClient, registered.clientId, secret)
    }
}

/** 브라우저에서 스크립트·내용으로 해석되거나 다른 앱을 여는 스킴. redirect 주소로 받지 않는다 */
private val BLOCKED_SCHEMES = setOf("javascript", "data", "vbscript", "file", "about", "blob", "filesystem")
private val WEB_SCHEMES = setOf("http", "https")
private const val RESERVED_SCOPE_PREFIX = "iam."
