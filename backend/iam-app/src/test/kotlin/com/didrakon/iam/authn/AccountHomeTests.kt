package com.didrakon.iam.authn

import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.login.AccountHomeController
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.common.error.BusinessRuleException
import org.hamcrest.Matchers.containsString
import org.hamcrest.Matchers.not
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals

/** IAM 홈(내 계정): 내 앱, 로그인된 기기·다른 기기 로그아웃, 최근 로그인 기록 */
@IntegrationTest
class AccountHomeTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val clientService: SsoClientService,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val fixture: AuthzFixture,
) {
    private val password = "correct-horse-battery"

    @Test
    fun `앱 시작 주소가 있는 켜진 클라이언트만 내 앱에 나오고 로그인 기록이 보인다`() {
        val shown = "홈앱${System.nanoTime()}"
        val hidden = "숨김${System.nanoTime()}"
        register(shown, "https://erp.example.com/")
        register(hidden, null)
        val (_, session) = login()

        mockMvc.perform(get("/").session(session))
            .andExpect(status().isOk)
            .andExpect(content().string(containsString(shown)))
            .andExpect(content().string(containsString("https://erp.example.com/")))
            .andExpect(content().string(not(containsString(hidden))))
            .andExpect(content().string(containsString("지금 이 기기")))
            .andExpect(content().string(containsString("최근 로그인 기록")))
    }

    @Test
    fun `다른 기기에서 모두 로그아웃하면 이 기기만 남는다`() {
        val (userId, loginId) = account()
        val here = login(loginId)
        val other = login(loginId)
        assertEquals(2, sessionService.activeSessions(userId).size)

        mockMvc.perform(post("/account/sessions/revoke-others").session(here).with(csrf()))
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/?signedOut=1"))

        assertEquals(1, sessionService.activeSessions(userId).size)
        mockMvc.perform(get("/").session(here)).andExpect(status().isOk)
        mockMvc.perform(get("/").session(other)).andExpect(status().is3xxRedirection)
    }

    @Test
    fun `앱 시작 주소는 http(s) 절대 주소만 받는다`() {
        assertThrows<BusinessRuleException> { register("잘못${System.nanoTime()}", "javascript:alert(1)") }
    }

    @Test
    fun `로그인하지 않으면 홈은 로그인 화면으로 보낸다`() {
        mockMvc.perform(get("/")).andExpect(status().is3xxRedirection)
    }

    @Test
    fun `User-Agent 를 브라우저·운영체제로 줄인다`() {
        assertEquals(
            "Chrome · macOS",
            AccountHomeController.deviceOf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0 Safari/537.36"),
        )
        assertEquals("Safari · iOS", AccountHomeController.deviceOf("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 Version/18.0 Mobile/15E148 Safari/604.1"))
        assertEquals("알 수 없는 기기", AccountHomeController.deviceOf(null))
        assertEquals("이 컴퓨터", AccountHomeController.ipOf("0:0:0:0:0:0:0:1"))
        assertEquals("203.0.113.7", AccountHomeController.ipOf("203.0.113.7"))
    }

    private fun register(name: String, homeUrl: String?) = clientService.register(
        ClientRegistration("home-${System.nanoTime()}", name, ClientType.WEB, redirectUris = setOf("https://app.example.com/cb"), homeUrl = homeUrl),
    )

    private fun account(): Pair<Long, String> {
        val userId = fixture.user()
        val loginId = "home${System.nanoTime()}"
        accountService.createAccount(userId, loginId, password)
        return userId to loginId
    }

    private fun login(): Pair<Long, MockHttpSession> {
        val (userId, loginId) = account()
        return userId to login(loginId)
    }

    private fun login(loginId: String): MockHttpSession {
        val session = MockHttpSession()
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(session).with(csrf()))
            .andExpect(status().is3xxRedirection)
        return session
    }
}
