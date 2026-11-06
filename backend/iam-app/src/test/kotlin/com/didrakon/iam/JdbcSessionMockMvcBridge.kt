package com.didrakon.iam

import jakarta.servlet.FilterChain
import jakarta.servlet.http.Cookie
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletRequestWrapper
import jakarta.servlet.http.HttpServletResponse
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.session.SessionRepository
import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.util.WebUtils
import java.util.Base64

/**
 * MockMvc 의 [MockHttpSession] 을 실제 세션 저장소(Spring Session JDBC)와 잇는다.
 * Spring Session 은 세션을 쿠키로 찾으므로 `.session(mockSession)` 을 무시한다. 이 필터가 브라우저 대신 세션 쿠키를 들고 다닌다:
 * - 요청 전: MockHttpSession 에 기억해 둔 세션 ID 를 쿠키로 붙인다
 * - 요청 후: 응답의 세션 쿠키(새 세션·ID 교체·무효화)를 기억하고, DB 에서 다시 읽은 속성을 MockHttpSession 에 비춰 둔다.
 *   테스트는 그대로 session.getAttribute 로 확인하고, 그 값은 JDK 직렬화·DB 저장을 한 번 거친 것이다
 *
 * Spring Session 필터보다 먼저 돌아야 하므로 가장 앞 순서로 등록한다 (MockMvc 에만 의미가 있다. 실제 요청에는 MockHttpSession 이 없다).
 */
class JdbcSessionMockMvcBridge(private val sessions: SessionRepository<*>) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val mock = request.getSession(false) as? MockHttpSession
        if (mock == null) {
            filterChain.doFilter(request, response)
            return
        }
        val sessionId = mock.getAttribute(SESSION_ID) as? String
        filterChain.doFilter(if (sessionId == null) request else WithSessionCookie(request, sessionId), response)

        val cookie = WebUtils.getNativeResponse(response, MockHttpServletResponse::class.java)?.cookies?.lastOrNull { it.name == COOKIE_NAME }
        if (cookie != null) {
            if (cookie.maxAge == 0 || cookie.value.isNullOrEmpty()) mock.removeAttribute(SESSION_ID)
            else mock.setAttribute(SESSION_ID, String(Base64.getDecoder().decode(cookie.value)))
        }
        mirror(mock)
    }

    private fun mirror(mock: MockHttpSession) {
        val sessionId = mock.getAttribute(SESSION_ID) as? String
        mock.attributeNames.toList().filter { it != SESSION_ID }.forEach(mock::removeAttribute)
        val stored = sessionId?.let(sessions::findById) ?: return
        stored.attributeNames.forEach { mock.setAttribute(it, stored.getAttribute(it)) }
    }

    private class WithSessionCookie(request: HttpServletRequest, sessionId: String) : HttpServletRequestWrapper(request) {
        private val cookies = request.cookies.orEmpty().filter { it.name != COOKIE_NAME }.toTypedArray() +
            Cookie(COOKIE_NAME, Base64.getEncoder().encodeToString(sessionId.toByteArray()))

        override fun getCookies(): Array<Cookie> = cookies
    }

    companion object {
        /** MockHttpSession 에 기억해 두는 Spring Session ID */
        const val SESSION_ID = "test.springSessionId"
        const val COOKIE_NAME = "JSESSIONID"
    }
}
