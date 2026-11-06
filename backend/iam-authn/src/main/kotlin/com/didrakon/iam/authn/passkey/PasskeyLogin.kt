package com.didrakon.iam.authn.passkey

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.event.AuthenticationEventType
import com.didrakon.iam.authn.event.AuthenticationEventWriter
import com.didrakon.iam.authn.event.AuthenticationResult
import com.didrakon.iam.authn.event.LoginFailedEvent
import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.login.LoginMethod
import com.didrakon.iam.authn.login.LoginOutcome
import com.didrakon.iam.authn.login.LoginSuccessHandler
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.ApplicationEventPublisher
import org.springframework.http.MediaType
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.core.userdetails.User
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.stereotype.Component
import org.springframework.web.filter.OncePerRequestFilter
import tools.jackson.databind.json.JsonMapper

private val json: JsonMapper = JsonMapper.builder().build()

/** 로그인 화면의 스크립트(iam-login/passkey.js)가 읽는 응답. 성공·실패 모두 [redirectUrl] 로 이동한다 */
private fun writeResult(response: HttpServletResponse, status: Int, authenticated: Boolean, redirectUrl: String) {
    response.status = status
    response.contentType = MediaType.APPLICATION_JSON_VALUE
    response.characterEncoding = Charsets.UTF_8.name()
    response.writer.write(json.writeValueAsString(mapOf("authenticated" to authenticated, "redirectUrl" to redirectUrl)))
}

/**
 * 패스키 로그인 성공 (POST /login/webauthn). 비밀번호 로그인과 같은 [LoginSuccessHandler.complete] 를 거친다.
 * Spring 의 WebAuthnAuthentication 은 principal 이 WebAuthn 사용자 정보라 SAS 가 인가 기록에 저장하지 못하므로,
 * 비밀번호·TOTP 로그인과 같은 표준 토큰(principal = subject ID 의 User, 권한 = 패스키 인증 요소만)으로 바꿔 세션에 둔다.
 */
@Component
class PasskeyLoginSuccessHandler(private val loginSuccessHandler: LoginSuccessHandler) : AuthenticationSuccessHandler {
    private val contextRepository = HttpSessionSecurityContextRepository()
    private val requestCache = HttpSessionRequestCache()

    override fun onAuthenticationSuccess(request: HttpServletRequest, response: HttpServletResponse, authentication: Authentication) {
        // Spring 이 준 패스키 인증 요소(FactorGrantedAuthority)를 그대로 쓴다. SAS 는 그 발급 시각으로 ID 토큰 auth_time 을 정한다
        val authorities = authentication.authorities.filter { it.authority == AuthFactors.WEBAUTHN }
        check(authorities.isNotEmpty()) { "패스키 인증 요소가 없습니다" }
        val principal = User.withUsername(authentication.name).password("").authorities(authorities).build()
        val login = UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities)
        val context = SecurityContextHolder.createEmptyContext().apply { this.authentication = login }
        SecurityContextHolder.setContext(context)
        contextRepository.saveContext(context, request, response)

        when (val outcome = loginSuccessHandler.complete(request, login, LoginMethod.PASSKEY)) {
            is LoginOutcome.Rejected -> writeResult(response, HttpServletResponse.SC_FORBIDDEN, false, outcome.url)
            LoginOutcome.Completed -> writeResult(
                response, HttpServletResponse.SC_OK, true,
                requestCache.getRequest(request, response)?.redirectUrl ?: "${request.contextPath}/",
            )
            LoginOutcome.MfaRequired -> throw IllegalStateException("패스키 로그인은 TOTP 를 요구하지 않습니다")
        }
    }
}

/**
 * 패스키 로그인 실패: 인증 이벤트(FAILED_LOGIN, 사유 PASSKEY: …)와 감사 기록을 남긴다.
 * 비밀번호 실패 횟수에는 넣지 않는다 (비밀번호 추측과 무관하다).
 */
@Component
class PasskeyLoginFailureHandler(
    private val accountService: LocalAccountService,
    private val eventWriter: AuthenticationEventWriter,
    private val eventPublisher: ApplicationEventPublisher,
) : AuthenticationFailureHandler {
    override fun onAuthenticationFailure(request: HttpServletRequest, response: HttpServletResponse, exception: AuthenticationException) {
        val unavailable = exception.cause as? PasskeyAccountUnavailableException
        val identity = unavailable?.let { accountService.findLocalIdentity(it.subjectId) }
        val reason = "PASSKEY: " + (exception.cause ?: exception).javaClass.simpleName
        eventWriter.write(
            AuthenticationEventType.FAILED_LOGIN, AuthenticationResult.FAILURE, unavailable?.subjectId, identity?.id,
            request.remoteAddr, request.getHeader("User-Agent"), reason,
        )
        eventPublisher.publishEvent(LoginFailedEvent(identity?.externalId ?: "(passkey)", unavailable?.subjectId, reason, request.remoteAddr))
        writeResult(
            response, HttpServletResponse.SC_UNAUTHORIZED, false,
            request.contextPath + if (unavailable != null) "/login?unavailable" else "/login?passkey",
        )
    }
}

/**
 * 패스키 등록·삭제(/webauthn/register 아래 전부)는 2단계 인증(TOTP 또는 패스키)을 거친 로그인에서만 받는다.
 * 비밀번호만 훔친 사람이 자기 패스키를 심어 MFA 를 우회하지 못하게 한다.
 * 보안 필터 체인에만 넣는다 (서블릿 필터로 자동 등록하지 않도록 빈으로 만들지 않는다).
 */
class PasskeyRegistrationGuardFilter : OncePerRequestFilter() {
    // Spring 의 WebAuthn 등록 필터와 같은 방식(디코딩한 경로)으로 맞춘다. 문자열 비교면 /webauthn/%72egister 같은 표기로 이 검사를 건너뛴다
    private val registerEndpoints = PathPatternRequestMatcher.withDefaults().matcher("$REGISTER_PATH/**")

    override fun shouldNotFilter(request: HttpServletRequest): Boolean = !registerEndpoints.matches(request)

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val user = SecurityContextHolder.getContext().authentication?.takeIf { it.isAuthenticated && it !is AnonymousAuthenticationToken }
        when {
            user == null -> response.sendError(HttpServletResponse.SC_UNAUTHORIZED)
            !AuthFactors.isMultiFactor(user) ->
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "패스키를 등록하려면 2단계 인증을 거친 로그인이 필요합니다")
            else -> filterChain.doFilter(request, response)
        }
    }

    companion object {
        const val REGISTER_PATH = "/webauthn/register"
    }
}
