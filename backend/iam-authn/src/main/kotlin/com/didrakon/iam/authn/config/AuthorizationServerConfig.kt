package com.didrakon.iam.authn.config

import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.OAuth2AuthenticationException
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2ErrorCodes
import org.springframework.beans.factory.ObjectProvider
import com.didrakon.iam.authn.token.UserTokenClaims
import com.didrakon.iam.authn.login.LoginFailureHandler
import com.didrakon.iam.authn.session.LoginSessionRepository
import com.didrakon.iam.authn.token.TokenRevoker
import com.didrakon.iam.authn.token.SessionLinkingAuthorizationService
import com.didrakon.iam.authn.client.ActiveClientRepository
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.login.LoginSessionLogoutHandler
import com.didrakon.iam.authn.login.LoginSessionValidationFilter
import com.didrakon.iam.authn.login.LoginSuccessHandler
import com.didrakon.iam.authn.login.MfaEnforcementFilter
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.passkey.PasskeyAccounts
import com.didrakon.iam.authn.passkey.PasskeyLoginFailureHandler
import com.didrakon.iam.authn.passkey.PasskeyLoginSuccessHandler
import com.didrakon.iam.authn.passkey.PasskeyPageController
import com.didrakon.iam.authn.passkey.PasskeyRegistrationGuardFilter
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authn.token.HashingOAuth2AuthorizationService
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpMethod
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.config.ObjectPostProcessor
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.core.Authentication
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.oidc.web.authentication.OidcLogoutAuthenticationSuccessHandler
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint
import org.springframework.security.web.authentication.session.ChangeSessionIdAuthenticationStrategy
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.security.web.webauthn.authentication.WebAuthnAuthenticationFilter
import org.springframework.security.web.authentication.logout.CompositeLogoutHandler
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

/**
 * IdP(Spring Authorization Server) 설정. 필터 체인 순서:
 * 1. OAuth2·OIDC 엔드포인트 (이 클래스)
 * 2. /api/ ** 리소스 서버 (iam-app)
 * 3. 로그인·MFA 화면 등 나머지 (이 클래스)
 */
@Configuration
@EnableConfigurationProperties(AuthnProperties::class)
class AuthorizationServerConfig(
    private val properties: AuthnProperties,
) {
    @Bean
    @Order(1)
    fun authorizationServerFilterChain(
        http: HttpSecurity,
        mfaService: MfaService,
        ssoClientRepository: SsoClientRepository,
        sessionService: LoginSessionService,
        logoutHandler: LoginSessionLogoutHandler,
    ): SecurityFilterChain {
        // RP 가 시작한 로그아웃(/connect/logout)에서도 로그인 세션을 닫고 기록을 남긴 뒤 HTTP 세션을 버린다
        val oidcLogoutResponse = OidcLogoutAuthenticationSuccessHandler().apply {
            setLogoutHandler(CompositeLogoutHandler(logoutHandler, SecurityContextLogoutHandler()))
        }
        http
            .oauth2AuthorizationServer { server ->
                http.securityMatcher(server.endpointsMatcher)
                server.oidc { oidc ->
                    oidc.logoutEndpoint { it.logoutResponseHandler(oidcLogoutResponse) }
                    // OIDC Back-Channel Logout: 등록한 클라이언트에 로그아웃 토큰을 보내고, 세션 단위면 sid 를 넣는다
                    oidc.providerConfigurationEndpoint { endpoint ->
                        endpoint.providerConfigurationCustomizer {
                            it.claim("backchannel_logout_supported", true).claim("backchannel_logout_session_supported", true)
                        }
                    }
                }
            }
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            // 브라우저 요청은 로그인 화면으로, API 호출은 401 로
            .exceptionHandling {
                it.defaultAuthenticationEntryPointFor(LoginUrlAuthenticationEntryPoint("/login"), MediaTypeRequestMatcher(MediaType.TEXT_HTML))
            }
            .addFilterBefore(LoginSessionValidationFilter(sessionService), AbstractPreAuthenticatedProcessingFilter::class.java)
            .addFilterBefore(MfaEnforcementFilter(mfaService, ssoClientRepository), AbstractPreAuthenticatedProcessingFilter::class.java)
        return http.build()
    }

    @Bean
    @Order(3)
    fun loginFilterChain(
        http: HttpSecurity,
        successHandler: LoginSuccessHandler,
        failureHandler: LoginFailureHandler,
        logoutHandler: LoginSessionLogoutHandler,
        mfaService: MfaService,
        ssoClientRepository: SsoClientRepository,
        sessionService: LoginSessionService,
        passkeySuccessHandler: PasskeyLoginSuccessHandler,
        passkeyFailureHandler: PasskeyLoginFailureHandler,
        passkeyAccounts: PasskeyAccounts,
    ): SecurityFilterChain {
        // 로그인 뒤 돌아갈 곳은 인가 요청(1번 체인이 저장)과 패스키 관리 화면뿐이다.
        // 다른 주소를 여기서 저장하면 favicon·CSS·다른 탭이 연 IAM 주소가 인가 요청을 덮어쓴다
        val returnTargets = HttpSessionRequestCache().apply {
            setRequestMatcher(PathPatternRequestMatcher.withDefaults().matcher(HttpMethod.GET, PasskeyPageController.PATH))
        }
        // 패스키 로그인의 계정 조회(WebAuthn 사용자 이름 = subject ID). 비밀번호 로그인의 UserDetailsService 빈과 따로 둔다
        http.setSharedObject(UserDetailsService::class.java, UserDetailsService(passkeyAccounts::loadUser))
        http
            .authorizeHttpRequests {
                it.requestMatchers("/login", "/login/password", "/login/forgot", "/error", "/actuator/health", "/iam-login/**").permitAll()
                    .anyRequest().authenticated()
            }
            .formLogin { it.loginPage("/login").successHandler(successHandler).failureHandler(failureHandler) }
            // 패스키: 로그인 POST /login/webauthn(옵션 /webauthn/authenticate/options), 등록 /webauthn/register(옵션 /webauthn/register/options).
            // 신뢰 당사자 설정(rpId·허용 출처·사용자 확인 필수)은 PasskeyConfig 의 빈이 정한다
            .webAuthn {
                it.disableDefaultRegistrationPage(true)
                it.withObjectPostProcessor(
                    object : ObjectPostProcessor<WebAuthnAuthenticationFilter> {
                        override fun <O : WebAuthnAuthenticationFilter> postProcess(filter: O): O = filter.apply {
                            setAuthenticationSuccessHandler(passkeySuccessHandler)
                            setAuthenticationFailureHandler(passkeyFailureHandler)
                            // 폼 로그인과 같이 로그인하면 세션 ID 와 CSRF 토큰을 바꾼다 (세션 고정 방지)
                            setSessionAuthenticationStrategy(
                                CompositeSessionAuthenticationStrategy(
                                    listOf(ChangeSessionIdAuthenticationStrategy(), CsrfAuthenticationStrategy(HttpSessionCsrfTokenRepository())),
                                ),
                            )
                        }
                    },
                )
            }
            .requestCache { it.requestCache(returnTargets) }
            .logout { it.addLogoutHandler(logoutHandler) }
            .addFilterBefore(LoginSessionValidationFilter(sessionService), AbstractPreAuthenticatedProcessingFilter::class.java)
            .addFilterBefore(MfaEnforcementFilter(mfaService, ssoClientRepository), AbstractPreAuthenticatedProcessingFilter::class.java)
            .addFilterBefore(PasskeyRegistrationGuardFilter(), AbstractPreAuthenticatedProcessingFilter::class.java)
        return http.build()
    }

    @Bean
    fun passwordEncoder(): PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()

    @Bean
    fun registeredClientRepository(jdbcTemplate: JdbcTemplate, ssoClientRepository: SsoClientRepository): RegisteredClientRepository =
        ActiveClientRepository(JdbcRegisteredClientRepository(jdbcTemplate), ssoClientRepository)

    @Bean
    fun authorizationService(
        jdbcTemplate: JdbcTemplate,
        clients: RegisteredClientRepository,
        sessionRepository: LoginSessionRepository,
        tokenRevoker: TokenRevoker,
    ): OAuth2AuthorizationService = SessionLinkingAuthorizationService(
        HashingOAuth2AuthorizationService(JdbcOAuth2AuthorizationService(jdbcTemplate, clients)), sessionRepository, tokenRevoker,
    )

    @Bean
    fun authorizationConsentService(jdbcTemplate: JdbcTemplate, clients: RegisteredClientRepository): OAuth2AuthorizationConsentService =
        JdbcOAuth2AuthorizationConsentService(jdbcTemplate, clients)

    @Bean
    fun authorizationServerSettings(): AuthorizationServerSettings = AuthorizationServerSettings.builder().issuer(properties.issuer).build()

    /**
     * - amr(인증 방법, RFC 8176): 비밀번호만이면 [pwd], TOTP 까지면 [pwd, otp], 패스키면 [hwk, user] (키 소지 + 사용자 확인).
     *   권한 판정의 SESSION 속성으로 쓴다
     * - 사용자 토큰(접근·ID 토큰)에는 [UserTokenClaims] 가 주는 사번·소속·역할을 더한다. 시스템 간 토큰(client credentials)에는 넣지 않는다
     */
    @Bean
    fun tokenCustomizer(
        userClaims: ObjectProvider<UserTokenClaims>,
        ssoClientRepository: SsoClientRepository,
        loginSessionService: LoginSessionService,
    ): OAuth2TokenCustomizer<JwtEncodingContext> = OAuth2TokenCustomizer { context ->
        // refresh 는 그 토큰이 나온 로그인 세션이 살아 있을 때만 (로그인 세션 상한 8시간을 refresh 로 넘기지 못하게)
        val authorization = context.authorization
        if (context.authorizationGrantType == AuthorizationGrantType.REFRESH_TOKEN && authorization != null &&
            !loginSessionService.allowsRefresh(authorization.id)
        ) {
            throw OAuth2AuthenticationException(OAuth2Error(OAuth2ErrorCodes.INVALID_GRANT, "로그인 세션이 끝났습니다. 다시 로그인하세요", null))
        }
        val authorities = context.getPrincipal<Authentication>()?.authorities.orEmpty().map { it.authority }
        // claim 은 authorization 에 직렬화되어 저장되고 SAS 는 허용된 타입만 다시 읽는다. Kotlin 내부 리스트 타입은 거부되므로 ArrayList 를 쓴다
        val amr = ArrayList<String>()
        if (AuthFactors.PASSWORD in authorities) amr.add("pwd")
        if (AuthFactors.TOTP in authorities) amr.add("otp")
        if (AuthFactors.WEBAUTHN in authorities) amr.addAll(listOf("hwk", "user"))
        if (amr.isNotEmpty()) context.claims.claim("amr", amr)

        if (context.authorizationGrantType == AuthorizationGrantType.CLIENT_CREDENTIALS) return@OAuth2TokenCustomizer
        val subjectId = context.getPrincipal<Authentication>()?.name?.toLongOrNull() ?: return@OAuth2TokenCustomizer
        // Supabase Third-Party Auth 는 role = "authenticated" 인 JWT 만 로그인한 사용자로 본다. 켠 클라이언트에만 넣는다
        if (ssoClientRepository.findByRegisteredClientId(context.registeredClient.id)?.supabaseRoleClaim == true) {
            context.claims.claim("role", "authenticated")
        }
        userClaims.ifAvailable { provider -> provider.claimsOf(subjectId).forEach { (name, value) -> context.claims.claim(name, value) } }
    }

    @Bean
    fun rsaKey(): RSAKey {
        val (publicKey, privateKey) = if (properties.jwtPrivateKey.isNotBlank()) {
            readPem(properties.jwtPublicKey, properties.jwtPrivateKey)
        } else {
            check(!properties.requirePersistentJwtKey) {
                "JWT 서명 키(IAM_JWT_PRIVATE_KEY, IAM_JWT_PUBLIC_KEY)가 없습니다. 운영에서는 재기동해도 토큰이 유지되도록 고정 키가 필요합니다"
            }
            // 개발용. 재기동하면 이전 토큰을 검증할 수 없다
            KeyPairGenerator.getInstance("RSA").apply { initialize(2048) }.generateKeyPair()
                .let { it.public as RSAPublicKey to it.private as RSAPrivateKey }
        }
        return RSAKey.Builder(publicKey).privateKey(privateKey).keyID("iam-${publicKey.modulus.hashCode()}").build()
    }

    @Bean
    fun jwkSource(rsaKey: RSAKey): JWKSource<SecurityContext> = ImmutableJWKSet(JWKSet(rsaKey))

    /** OIDC userinfo 와 /api 리소스 서버가 함께 쓴다. 서명과 iss 를 검증한다 */
    @Bean
    fun jwtDecoder(rsaKey: RSAKey): JwtDecoder =
        NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build().apply {
            setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer))
        }

    private fun readPem(publicPem: String, privatePem: String): Pair<RSAPublicKey, RSAPrivateKey> {
        fun body(pem: String) = Base64.getMimeDecoder().decode(pem.lines().filterNot { it.startsWith("-----") }.joinToString(""))
        val factory = KeyFactory.getInstance("RSA")
        return factory.generatePublic(X509EncodedKeySpec(body(publicPem))) as RSAPublicKey to
            factory.generatePrivate(PKCS8EncodedKeySpec(body(privatePem))) as RSAPrivateKey
    }
}
