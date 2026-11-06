package com.didrakon.iam.api.support

import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.common.context.RequestContext
import com.didrakon.iam.common.context.RequestContextHolder
import com.didrakon.iam.common.crypto.randomUrlSafe
import com.nimbusds.jose.jwk.RSAKey
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.annotation.Order
import org.springframework.http.HttpStatus
import org.springframework.http.MediaType
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2Error
import org.springframework.security.oauth2.core.OAuth2TokenValidator
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult
import org.springframework.security.oauth2.jwt.Jwt
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.JwtValidators
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken
import org.springframework.security.oauth2.server.resource.web.authentication.BearerTokenAuthenticationFilter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.filter.OncePerRequestFilter
import tools.jackson.databind.json.JsonMapper

/** 지금 요청의 인증 주체 */
object ApiPrincipal {
    /** 사람·서비스 계정 subject ID. client credentials 토큰(sub = aud = client_id)이면 null */
    fun subjectId(): Long? {
        val authentication = SecurityContextHolder.getContext().authentication ?: return null
        if (authentication is JwtAuthenticationToken && authentication.token.subject in authentication.token.audience.orEmpty()) return null
        return authentication.name?.toLongOrNull()
    }

    fun requireSubjectId(): Long =
        subjectId() ?: throw ApiException(HttpStatus.FORBIDDEN, "SUBJECT_REQUIRED", "사용자 또는 서비스 계정으로 호출해야 합니다")

    /** 토큰의 amr(인증 방법). API 키는 비어 있다 */
    fun authenticationMethods(): List<String> =
        (SecurityContextHolder.getContext().authentication as? JwtAuthenticationToken)?.token?.getClaimAsStringList("amr").orEmpty()

    /** JWT(로그인으로 받은 토큰)로 인증했으면 true. API 키는 false */
    fun isJwt(): Boolean = SecurityContextHolder.getContext().authentication is JwtAuthenticationToken

    fun hasScope(scope: String): Boolean =
        SecurityContextHolder.getContext().authentication?.authorities.orEmpty().any { it.authority == "SCOPE_$scope" }
}

/** X-API-Key 로 들어온 요청을 키 소유 subject 로 인증한다 */
class ApiKeyAuthentication(private val subjectId: Long, private val apiKeyId: Long) :
    AbstractAuthenticationToken(AuthorityUtils.createAuthorityList("AUTH_API_KEY")) {
    init {
        isAuthenticated = true
    }

    override fun getName(): String = subjectId.toString()

    override fun getPrincipal(): Any = subjectId

    override fun getCredentials(): Any = apiKeyId
}

class ApiKeyAuthenticationFilter(private val apiKeyService: ApiKeyService) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val rawKey = request.getHeader(HEADER)
        if (rawKey != null && SecurityContextHolder.getContext().authentication == null) {
            val apiKey = apiKeyService.authenticate(rawKey)
            if (apiKey == null) {
                writeError(response, HttpStatus.UNAUTHORIZED, "INVALID_API_KEY", "API 키가 유효하지 않습니다")
                return
            }
            SecurityContextHolder.getContext().authentication = ApiKeyAuthentication(apiKey.subjectId, apiKey.requireId())
        }
        filterChain.doFilter(request, response)
    }

    companion object {
        const val HEADER = "X-API-Key"
    }
}

/** 인증 뒤에 행위자·trace·IP 를 [RequestContextHolder] 에 넣어 감사 기록이 읽게 한다. trace ID 는 응답 헤더로 돌려준다 */
class RequestContextFilter : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val traceId = request.getHeader(TRACE_HEADER)?.takeIf { it.length <= 64 && it.isNotBlank() } ?: randomUrlSafe(16)
        response.setHeader(TRACE_HEADER, traceId)
        val context = RequestContext(
            actorSubjectId = ApiPrincipal.subjectId(),
            traceId = traceId,
            ipAddress = request.remoteAddr,
            userAgent = request.getHeader("User-Agent"),
        )
        RequestContextHolder.runWith(context) { filterChain.doFilter(request, response) }
    }

    companion object {
        const val TRACE_HEADER = "X-Trace-Id"
    }
}

private val errorWriter: JsonMapper = JsonMapper.builder().build()

private fun writeError(response: HttpServletResponse, status: HttpStatus, code: String, message: String) {
    response.status = status.value()
    response.contentType = MediaType.APPLICATION_JSON_VALUE
    response.characterEncoding = Charsets.UTF_8.name()
    response.writer.write(errorWriter.writeValueAsString(ApiResponse.error(code, message)))
}

/**
 * /api 가 받는 JWT 를 가린다. 같은 키로 서명한 토큰이라도 다른 연동 시스템을 위해 발급된 것은 받지 않는다.
 * - ID 토큰(azp 가 있다)은 받지 않는다. 로그인 결과를 알려 주는 용도이지 API 호출용이 아니다
 * - 시스템 간 토큰(client credentials: sub = aud = client_id)은 받는다. 권한은 PermissionInterceptor 가 판정한다
 * - 사람의 토큰은 관리 콘솔(iam-admin)에 발급된 것만 받는다. 다른 시스템이 받은 사용자 토큰으로 관리 API 를 부르지 못하게 한다
 */
class ApiTokenValidator(private val consoleClientId: String) : OAuth2TokenValidator<Jwt> {
    override fun validate(token: Jwt): OAuth2TokenValidatorResult {
        val audience = token.audience.orEmpty()
        return when {
            token.hasClaim("azp") -> failure("ID 토큰은 API 호출에 쓸 수 없습니다")
            token.subject in audience -> OAuth2TokenValidatorResult.success()
            consoleClientId in audience -> OAuth2TokenValidatorResult.success()
            else -> failure("이 API 용으로 발급된 토큰이 아닙니다")
        }
    }

    private fun failure(description: String) = OAuth2TokenValidatorResult.failure(OAuth2Error("invalid_token", description, null))
}

/** /api 는 세션 없는 리소스 서버. IAM 이 발급한 JWT 나 API 키로 인증하고, 인가는 [PermissionInterceptor] 가 PDP 로 한다 */
@Configuration
class ApiSecurityConfig {
    @Bean
    @Order(2)
    fun apiFilterChain(http: HttpSecurity, apiKeyService: ApiKeyService, rsaKey: RSAKey, properties: AuthnProperties): SecurityFilterChain {
        http
            .securityMatcher("/api/**")
            .sessionManagement { it.sessionCreationPolicy(SessionCreationPolicy.STATELESS) }
            .csrf { it.disable() } // 쿠키가 아니라 Authorization·X-API-Key 헤더로만 인증한다
            .authorizeHttpRequests { it.anyRequest().authenticated() }
            .oauth2ResourceServer { it.jwt { jwt -> jwt.decoder(apiJwtDecoder(rsaKey, properties.issuer)) } }
            .exceptionHandling {
                it.authenticationEntryPoint { _, response, _ -> writeError(response, HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED", "인증이 필요합니다") }
                it.accessDeniedHandler { _, response, _ -> writeError(response, HttpStatus.FORBIDDEN, "FORBIDDEN", "권한이 없습니다") }
            }
            .addFilterBefore(ApiKeyAuthenticationFilter(apiKeyService), BearerTokenAuthenticationFilter::class.java)
            .addFilterAfter(RequestContextFilter(), BearerTokenAuthenticationFilter::class.java)
        return http.build()
    }

    /** userinfo 와 함께 쓰는 JwtDecoder 빈과 별개로, 서명·iss 검증에 [ApiTokenValidator] 를 더한다 */
    private fun apiJwtDecoder(rsaKey: RSAKey, issuer: String): JwtDecoder =
        NimbusJwtDecoder.withPublicKey(rsaKey.toRSAPublicKey()).build().apply {
            setJwtValidator(DelegatingOAuth2TokenValidator(JwtValidators.createDefaultWithIssuer(issuer), ApiTokenValidator(ApiResources.CLIENT_CODE)))
        }
}
