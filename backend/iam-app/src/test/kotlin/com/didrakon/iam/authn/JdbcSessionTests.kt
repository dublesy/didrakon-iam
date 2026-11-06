package com.didrakon.iam.authn

import com.didrakon.iam.JdbcSessionMockMvcBridge
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.core.context.SecurityContextImpl
import org.springframework.security.core.userdetails.User
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.web.authentication.WebAuthenticationDetails
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.security.web.csrf.CsrfToken
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository
import org.springframework.security.web.savedrequest.HttpSessionRequestCache
import org.springframework.security.web.savedrequest.SavedRequest
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import java.net.URI
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * 브라우저 세션이 DB(Spring Session JDBC)에 저장되어 재기동·다른 인스턴스에서도 이어지는지 확인한다.
 * 세션에 두는 값은 모두 JDK 직렬화로 저장했다가 다시 읽을 수 있어야 한다.
 */
@IntegrationTest
class JdbcSessionTests @Autowired constructor(
    sessionRepository: FindByIndexNameSessionRepository<*>,
    private val mockMvc: MockMvc,
    private val clientService: SsoClientService,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    // JdbcIndexedSessionRepository 의 세션 타입(JdbcSession)은 패키지 밖에서 보이지 않아 Session 으로 다룬다
    @Suppress("UNCHECKED_CAST")
    private val sessions = sessionRepository as FindByIndexNameSessionRepository<Session>
    private val callback = "https://app.example.com/callback"
    private val password = "correct-horse-battery"

    @Test
    fun `보안 컨텍스트·돌아갈 요청·CSRF 토큰·로그인 세션 속성은 DB 에 저장했다가 그대로 다시 읽는다`() {
        val issuedAt = Instant.parse("2026-11-05T01:02:03.456789Z")
        val authorities = listOf(
            FactorGrantedAuthority.withAuthority(AuthFactors.PASSWORD).issuedAt(issuedAt).build(),
            FactorGrantedAuthority.withAuthority(AuthFactors.TOTP).issuedAt(issuedAt.plusSeconds(20)).build(),
        )
        val principalName = "subject-${System.nanoTime()}"
        val principal = User.withUsername(principalName).password("").authorities(authorities).build()
        val authentication = UsernamePasswordAuthenticationToken.authenticated(principal, null, authorities).apply {
            details = WebAuthenticationDetails("203.0.113.7", "previous-session")
        }
        val authorize = MockHttpServletRequest("GET", "/oauth2/authorize").apply {
            queryString = "response_type=code&client_id=web&state=s1"
            addParameter("response_type", "code")
            addParameter("client_id", "web")
            addParameter("state", "s1")
            session = MockHttpSession()
        }
        HttpSessionRequestCache().saveRequest(authorize, MockHttpServletResponse())
        val savedRequest = authorize.session?.getAttribute(SAVED_REQUEST) as SavedRequest
        val csrfToken = HttpSessionCsrfTokenRepository().generateToken(MockHttpServletRequest())

        val session = sessions.createSession().apply {
            setAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, SecurityContextImpl(authentication))
            setAttribute(SAVED_REQUEST, savedRequest)
            setAttribute(CSRF_TOKEN, csrfToken)
            setAttribute(AuthFactors.LOGIN_SESSION_KEY, "login-session-key")
            setAttribute(AuthFactors.MFA_PENDING, true)
        }
        sessions.save(session)

        val loaded = sessions.findById(session.id) ?: throw AssertionError("저장한 세션이 없습니다")
        val restored = loaded.getAttribute<SecurityContext>(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)?.authentication
            ?: throw AssertionError("인증 정보 없음")
        assertEquals(authentication, restored)
        // SAS 는 FactorGrantedAuthority 의 발급 시각으로 ID 토큰 auth_time 을 정한다
        assertEquals(authorities.map { it.issuedAt }, restored.authorities.map { (it as FactorGrantedAuthority).issuedAt })
        assertEquals(savedRequest.redirectUrl, loaded.getAttribute<SavedRequest>(SAVED_REQUEST)?.redirectUrl)
        assertEquals(csrfToken.token, loaded.getAttribute<CsrfToken>(CSRF_TOKEN)?.token)
        assertEquals("login-session-key", loaded.getAttribute<String>(AuthFactors.LOGIN_SESSION_KEY))
        assertEquals(true, loaded.getAttribute<Boolean>(AuthFactors.MFA_PENDING))
        // 사용자별 세션 조회(PRINCIPAL_NAME)는 subject ID 로 된다
        assertEquals(setOf(session.id), sessions.findByIndexNameAndIndexValue(FindByIndexNameSessionRepository.PRINCIPAL_NAME_INDEX_NAME, principalName).keys)

        sessions.deleteById(session.id)
    }

    @Test
    fun `로그인 전 authorize 요청은 DB 세션에 남아 쿠키만으로 로그인 뒤 code 발급까지 이어지고 세션 ID 는 바뀐다`() {
        val client = clientService.register(ClientRegistration("web-${System.nanoTime()}", "웹", ClientType.WEB, redirectUris = setOf(callback)))
        val loginId = account()
        val browser = MockHttpSession()

        mockMvc.perform(
            get(
                UriComponentsBuilder.fromPath("/oauth2/authorize")
                    .queryParam("response_type", "code").queryParam("client_id", client.clientId)
                    .queryParam("redirect_uri", callback).queryParam("scope", "openid").queryParam("state", "state-1")
                    .encode().build().toUriString(),
            ).session(browser).accept(MediaType.TEXT_HTML),
        ).andExpect(status().is3xxRedirection)
        val beforeLogin = sessionIdOf(browser)
        val saved = sessions.findById(beforeLogin)?.getAttribute<SavedRequest>(SAVED_REQUEST) ?: throw AssertionError("저장된 요청 없음")
        assertTrue("/oauth2/authorize" in saved.redirectUrl, saved.redirectUrl)

        // 서버 메모리에는 아무것도 없다고 보고(재기동·다른 인스턴스) 세션 쿠키만 가진 브라우저로 이어간다
        val cookieOnly = MockHttpSession().apply { setAttribute(JdbcSessionMockMvcBridge.SESSION_ID, beforeLogin) }
        val back = mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(cookieOnly).with(csrf()))
            .andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl ?: throw AssertionError("redirect 없음")
        assertTrue("/oauth2/authorize" in back, back)
        // 세션 고정 방지: 로그인하면 세션 ID 가 바뀌고 이전 ID 로는 찾을 수 없다
        val afterLogin = sessionIdOf(cookieOnly)
        assertNotEquals(beforeLogin, afterLogin)
        assertNull(sessions.findById(beforeLogin))
        assertNotNull(sessions.findById(afterLogin)?.getAttribute<String>(AuthFactors.LOGIN_SESSION_KEY))

        val nextRequest = MockHttpSession().apply { setAttribute(JdbcSessionMockMvcBridge.SESSION_ID, afterLogin) }
        val location = mockMvc.perform(get(URI.create(back)).session(nextRequest))
            .andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl ?: throw AssertionError("redirect 없음")
        assertTrue(location.startsWith(callback), location)
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code") ?: throw AssertionError("code 없음")
        mockMvc.perform(
            post("/oauth2/token").with(httpBasic(client.clientId, client.clientSecret ?: throw AssertionError("비밀값 없음")))
                .param("grant_type", "authorization_code").param("code", code).param("redirect_uri", callback),
        ).andExpect(status().isOk)
            // 서버 간 호출은 세션을 만들지 않는다 (세션 테이블이 호출마다 늘지 않게)
            .andExpect(header().doesNotExist("Set-Cookie"))
    }

    @Test
    fun `로그인 실패 시 세션에 남는 예외에는 입력한 비밀번호가 없다`() {
        val loginId = account()
        val browser = MockHttpSession()
        val typed = "typed-wrong-password-${System.nanoTime()}"

        mockMvc.perform(post("/login").param("username", loginId).param("password", typed).session(browser).with(csrf()))
            .andExpect(redirectedUrl("/login?error"))

        val stored = jdbc.queryForList(
            """
            SELECT a.ATTRIBUTE_BYTES FROM SPRING_SESSION_ATTRIBUTES a JOIN SPRING_SESSION s ON s.PRIMARY_ID = a.SESSION_PRIMARY_ID
            WHERE s.SESSION_ID = ?
            """,
            ByteArray::class.java, sessionIdOf(browser),
        )
        assertTrue(stored.isNotEmpty())
        assertFalse(stored.filterNotNull().any { String(it, Charsets.ISO_8859_1).contains(typed) })
        // 로그인 화면은 여전히 세션의 예외로 문구를 고른다
        mockMvc.perform(get("/login").param("error", "").session(browser)).andExpect(status().isOk)
    }

    @Test
    fun `세션 쿠키는 JSESSIONID·HttpOnly 이고, 로그인 세션을 끊으면 DB 의 브라우저 세션도 지워진다`() {
        val loginId = account()
        val browser = MockHttpSession()
        val cookie = mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(browser).with(csrf()))
            .andExpect(status().is3xxRedirection).andReturn().response.getHeader("Set-Cookie") ?: throw AssertionError("세션 쿠키 없음")
        // 쿠키는 이전(Tomcat 세션)과 같은 이름이고 스크립트로 읽을 수 없다
        assertTrue(cookie.startsWith("JSESSIONID=") && "HttpOnly" in cookie && "SameSite=Lax" in cookie, cookie)
        val sessionId = sessionIdOf(browser)
        val subjectId = accountService.findIdentity(loginId)?.subjectId ?: throw AssertionError("계정 없음")

        sessionService.revoke(sessionService.activeSessions(subjectId).single().requireId())
        mockMvc.perform(get("/").session(browser).accept(MediaType.TEXT_HTML)).andExpect(redirectedUrl("/login"))

        assertNull(sessions.findById(sessionId))
    }

    private fun account(): String {
        val loginId = "user${System.nanoTime()}"
        accountService.createAccount(fixture.user(), loginId, password)
        return loginId
    }

    private fun sessionIdOf(browser: MockHttpSession): String =
        browser.getAttribute(JdbcSessionMockMvcBridge.SESSION_ID) as? String ?: throw AssertionError("세션 쿠키 없음")

    companion object {
        const val SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST"
        val CSRF_TOKEN = HttpSessionCsrfTokenRepository::class.java.name + ".CSRF_TOKEN"
    }
}
