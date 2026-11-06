package com.didrakon.iam.authn.login

import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.session.LoginSessionService
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AnonymousAuthenticationToken
import org.springframework.security.core.Authentication
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher
import org.springframework.web.filter.OncePerRequestFilter

private fun currentUser(): Authentication? =
    SecurityContextHolder.getContext().authentication?.takeIf { it.isAuthenticated && it !is AnonymousAuthenticationToken }

private fun HttpServletRequest.path(): String = requestURI.removePrefix(contextPath)

/**
 * 브라우저 로그인 세션이 DB 에서 종료(관리자 강제 종료·만료)되었으면 HTTP 세션을 버려 다시 로그인하게 한다.
 * 보안 필터 체인에만 넣는다 (서블릿 필터로 자동 등록하지 않도록 빈으로 만들지 않는다).
 */
class LoginSessionValidationFilter(private val sessionService: LoginSessionService) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val session = request.getSession(false)
        val sessionKey = session?.getAttribute(AuthFactors.LOGIN_SESSION_KEY) as? String
        if (currentUser() != null && sessionKey != null && !sessionService.isValid(sessionKey)) {
            session.invalidate()
            SecurityContextHolder.clearContext()
        }
        filterChain.doFilter(request, response)
    }
}

/**
 * MFA 단계를 강제한다.
 * - 비밀번호만 통과한 세션(MFA_PENDING)은 MFA 화면과 로그아웃 외에는 갈 수 없다.
 *   MFA 화면이 쓰는 정적 자원(CSS·글꼴)은 통과시킨다. 막으면 그 요청이 "로그인 후 돌아갈 곳"을 덮어쓴다.
 * - require_mfa 클라이언트의 authorize 요청은 TOTP 또는 패스키 인증 요소가 있어야 한다. 등록된 TOTP 가 없으면 거부한다.
 */
class MfaEnforcementFilter(
    private val mfaService: MfaService,
    private val ssoClientRepository: SsoClientRepository,
) : OncePerRequestFilter() {
    private val requestCache = HttpSessionRequestCache()

    // SAS 의 authorize 엔드포인트와 같은 방식(디코딩한 경로)으로 맞춘다. 문자열 비교면 /oauth2/%61uthorize 같은 표기로 이 검사를 건너뛴다
    private val authorizeEndpoint = PathPatternRequestMatcher.withDefaults().matcher(AUTHORIZE_PATH)

    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val user = currentUser()
        val path = request.path()
        if (user == null || path == AuthFactors.MFA_PATH || path == "/logout" || path.startsWith(LOGIN_ASSETS_PATH)) {
            filterChain.doFilter(request, response)
            return
        }
        val session = request.getSession(false)
        if (session?.getAttribute(AuthFactors.MFA_PENDING) == true) {
            // 돌아갈 곳은 이미 정해졌다. 브라우저가 따로 보내는 요청(favicon 등)으로 덮어쓰지 않는다
            response.sendRedirect(request.contextPath + AuthFactors.MFA_PATH)
            return
        }
        if (authorizeEndpoint.matches(request) && !AuthFactors.isMultiFactor(user) && clientRequiresMfa(request)) {
            val subjectId = user.name.toLongOrNull()
            if (subjectId == null || !mfaService.hasVerifiedMethod(subjectId)) {
                response.sendError(HttpServletResponse.SC_FORBIDDEN, "이 시스템에 로그인하려면 MFA 등록이 필요합니다")
                return
            }
            request.session.setAttribute(AuthFactors.MFA_PENDING, true)
            // 이 authorize 요청이 MFA 뒤에 돌아갈 곳이다
            requestCache.saveRequest(request, response)
            response.sendRedirect(request.contextPath + AuthFactors.MFA_PATH)
            return
        }
        filterChain.doFilter(request, response)
    }

    private fun clientRequiresMfa(request: HttpServletRequest): Boolean =
        request.getParameter("client_id")?.let { ssoClientRepository.findByClientCode(it)?.requireMfa } ?: false


    companion object {
        const val AUTHORIZE_PATH = "/oauth2/authorize"
        const val LOGIN_ASSETS_PATH = "/iam-login/"
    }
}
