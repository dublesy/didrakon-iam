package com.didrakon.iam.authn

import com.didrakon.iam.JdbcSessionMockMvcBridge
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authn.session.AuthenticationLevel
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 로그인 실패 기록이 별도 트랜잭션으로 커밋되므로 롤백하지 않는 통합 테스트로 확인한다 */
@IntegrationTest
class LocalLoginTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val mfaService: MfaService,
    private val mfaMethodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    private val password = "correct-horse-battery"

    @Test
    fun `비밀번호 로그인에 성공하면 로그인 세션과 인증 이벤트가 남는다`() {
        val (userId, loginId) = account()
        val session = MockHttpSession()

        login(loginId, password, session).andExpect(status().is3xxRedirection).andExpect(redirectedUrl("/"))

        assertNotNull(session.getAttribute(AuthFactors.LOGIN_SESSION_KEY))
        assertEquals(listOf(AuthenticationLevel.PASSWORD), sessionService.activeSessions(userId).map { it.authenticationLevel })
        assertEquals(1, events(userId, "LOGIN", "SUCCESS"))
        assertEquals(listOf("LOGIN_SUCCESS"), auditActions(userId))
    }

    @Test
    fun `관리자가 초기화한 비밀번호는 다음 로그인에서 바꿔야 하고 바꾼 뒤 새 비밀번호로 들어간다`() {
        val (userId, loginId) = account()
        val identityId = accountService.findLocalIdentity(userId)?.requireId() ?: throw AssertionError()
        accountService.changePassword(identityId, "reset-by-admin-123", requireChangeOnNextLogin = true)
        val session = MockHttpSession()

        login(loginId, "reset-by-admin-123", session).andExpect(redirectedUrl("/login/password"))
        assertNull(session.getAttribute(AuthFactors.LOGIN_SESSION_KEY))
        mockMvc.perform(post("/login/password").param("newPassword", "brand-new-pass-1").param("confirmPassword", "different-pass-2").session(session).with(csrf()))
            .andExpect(status().isOk)
        mockMvc.perform(post("/login/password").param("newPassword", "brand-new-pass-1").param("confirmPassword", "brand-new-pass-1").session(session).with(csrf()))
            .andExpect(redirectedUrl("/login?changed"))

        login(loginId, "brand-new-pass-1").andExpect(redirectedUrl("/"))
    }

    @Test
    fun `만료·초기화된 비밀번호로 변경 화면에 갈 때 세션 ID 를 바꾼다 (로그인 전 세션 고정 방지)`() {
        val (userId, loginId) = account()
        val identityId = accountService.findLocalIdentity(userId)?.requireId() ?: throw AssertionError()
        accountService.changePassword(identityId, "reset-by-admin-123", requireChangeOnNextLogin = true)
        val session = MockHttpSession()
        // 로그인 화면을 열면 세션(CSRF 토큰)이 생긴다. 세션은 DB 에 있고 MockHttpSession 은 그 ID 만 들고 있다
        mockMvc.perform(get("/login").session(session)).andExpect(status().isOk)
        val before = session.getAttribute(JdbcSessionMockMvcBridge.SESSION_ID) ?: throw AssertionError("세션 없음")

        login(loginId, "reset-by-admin-123", session).andExpect(redirectedUrl("/login/password"))

        assertNotEquals(before, session.getAttribute(JdbcSessionMockMvcBridge.SESSION_ID))
    }

    @Test
    fun `만료된 비밀번호도 그 자리에서 바꾸고, 비밀번호를 틀리면 변경 화면으로 가지 않는다`() {
        val (userId, loginId) = account()
        jdbc.update(
            "UPDATE local_credential SET password_expire_at = NOW() - INTERVAL 1 DAY WHERE identity_id = ?",
            accountService.findLocalIdentity(userId)?.requireId(),
        )

        login(loginId, "wrong-password-0").andExpect(redirectedUrl("/login?error"))
        login(loginId, password).andExpect(redirectedUrl("/login/password"))
        mockMvc.perform(get("/login/password")).andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `연속 5회 실패하면 잠기고 올바른 비밀번호로도 로그인할 수 없다`() {
        val (userId, loginId) = account()

        repeat(5) { login(loginId, "wrong-password-0").andExpect(redirectedUrl("/login?error")) }
        login(loginId, password).andExpect(redirectedUrl("/login?error"))

        assertTrue(accountService.findCredential(loginId)?.isLockedAt(Instant.now()) ?: false)
        assertEquals(6, events(userId, "FAILED_LOGIN", "FAILURE"))
        val lastReason = jdbc.queryForObject(
            "SELECT failure_reason FROM authentication_event WHERE subject_id = ? ORDER BY authentication_event_id DESC LIMIT 1",
            String::class.java, userId,
        )
        assertEquals("LockedException", lastReason)
    }

    @Test
    fun `잠기기 전에 성공하면 실패 횟수가 초기화된다`() {
        val (_, loginId) = account()
        repeat(4) { login(loginId, "wrong-password-0") }

        login(loginId, password).andExpect(redirectedUrl("/"))

        assertEquals(0, accountService.findCredential(loginId)?.failedAttemptCount)
    }

    @Test
    fun `로그아웃하면 로그인 세션이 종료된다`() {
        val (userId, loginId) = account()
        val session = MockHttpSession()
        login(loginId, password, session)

        mockMvc.perform(post("/logout").session(session).with(csrf())).andExpect(status().is3xxRedirection)

        assertEquals(emptyList(), sessionService.activeSessions(userId))
        assertEquals(1, events(userId, "LOGOUT", "SUCCESS"))
        assertEquals(listOf("LOGIN_SUCCESS", "LOGOUT"), auditActions(userId))
    }

    @Test
    fun `관리자가 로그인 세션을 종료하면 다음 요청에서 다시 로그인해야 한다`() {
        val (userId, loginId) = account()
        val session = MockHttpSession()
        login(loginId, password, session)
        mockMvc.perform(get("/").session(session)).andExpect(status().isOk)

        sessionService.revoke(sessionService.activeSessions(userId).single().requireId())

        mockMvc.perform(get("/").session(MockHttpSession().also { copy(session, it) }))
            .andExpect(status().is3xxRedirection)
            .andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `MFA 를 등록한 사용자는 TOTP 를 거쳐야 하고 성공하면 세션이 MFA 수준이 된다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        val session = MockHttpSession()

        login(loginId, password, session).andExpect(redirectedUrl("/login/mfa"))
        mockMvc.perform(get("/some-page").session(session)).andExpect(redirectedUrl("/login/mfa"))
        mockMvc.perform(post("/login/mfa").param("code", wrongCode(secret)).session(session).with(csrf()))
            .andExpect(redirectedUrl("/login/mfa?error"))

        // 등록 확인에 쓴 구간의 코드는 재사용 방지로 거부되므로 다음 구간의 코드를 쓴다
        val result = mockMvc.perform(post("/login/mfa").param("code", Totp.code(secret, Instant.now().plusSeconds(30))).session(session).with(csrf()))
            .andExpect(status().is3xxRedirection).andReturn()

        assertNotEquals("/login/mfa", result.response.redirectedUrl)
        assertNull(session.getAttribute(AuthFactors.MFA_PENDING))
        assertEquals(listOf(AuthenticationLevel.MFA), sessionService.activeSessions(userId).map { it.authenticationLevel })
        assertEquals(1, events(userId, "MFA", "FAILURE"))
        assertEquals(1, events(userId, "MFA", "SUCCESS"))
    }

    @Test
    fun `MFA 화면의 CSS·글꼴 요청은 막지 않고, IAM 주소로 직접 들어왔으면 MFA 뒤 IAM 첫 화면으로 간다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        val session = MockHttpSession()
        mockMvc.perform(get("/some-page").session(session)).andExpect(status().is3xxRedirection)

        login(loginId, password, session).andExpect(redirectedUrl("/login/mfa"))
        mockMvc.perform(get("/iam-login/login.css").session(session)).andExpect(status().isOk)

        mockMvc.perform(post("/login/mfa").param("code", Totp.code(secret, Instant.now().plusSeconds(30))).session(session).with(csrf()))
            .andExpect(redirectedUrl("/"))
    }

    @Test
    fun `돌아갈 곳 없이 로그인하면 IAM 첫 화면에서 로그인 상태를 알려준다`() {
        val (_, loginId) = account()
        val session = MockHttpSession()

        login(loginId, password, session).andExpect(redirectedUrl("/"))
        mockMvc.perform(get("/").session(session)).andExpect(status().isOk)
    }

    @Test
    fun `MFA 코드를 5번 연속 틀리면 계정이 잠기고 로그인 시도가 끝난다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        val session = MockHttpSession()
        login(loginId, password, session).andExpect(redirectedUrl("/login/mfa"))

        repeat(4) {
            mockMvc.perform(post("/login/mfa").param("code", wrongCode(secret)).session(session).with(csrf()))
                .andExpect(redirectedUrl("/login/mfa?error"))
        }
        mockMvc.perform(post("/login/mfa").param("code", wrongCode(secret)).session(session).with(csrf()))
            .andExpect(redirectedUrl("/login?locked"))

        assertTrue(accountService.findCredential(loginId)?.isLockedAt(Instant.now()) ?: false)
        assertEquals(emptyList(), sessionService.activeSessions(userId))
        login(loginId, password).andExpect(redirectedUrl("/login?error"))
    }

    @Test
    fun `한 번 쓴 TOTP 코드는 다시 로그인할 때 쓸 수 없다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        // 등록 확인에 쓴 구간 다음 구간의 코드를 쓴다 (등록 확인 코드와 겹치지 않게)
        val code = Totp.code(secret, Instant.now().plusSeconds(30))

        val first = MockHttpSession()
        login(loginId, password, first)
        mockMvc.perform(post("/login/mfa").param("code", code).session(first).with(csrf()))
            .andExpect(status().is3xxRedirection)
            .andExpect { assertNotEquals("/login/mfa?error", it.response.redirectedUrl) }

        val second = MockHttpSession()
        login(loginId, password, second)
        mockMvc.perform(post("/login/mfa").param("code", code).session(second).with(csrf()))
            .andExpect(redirectedUrl("/login/mfa?error"))
    }

    @Test
    fun `확인을 마치지 않은 TOTP 는 로그인에 쓰지 않는다`() {
        val (userId, loginId) = account()
        mfaService.enrollTotp(userId, loginId)

        assertFalse(mfaService.hasVerifiedMethod(userId))
        login(loginId, password).andExpect(redirectedUrl("/"))
    }

    private fun account(): Pair<Long, String> {
        val userId = fixture.user()
        val loginId = "user${System.nanoTime()}"
        accountService.createAccount(userId, loginId, password)
        return userId to loginId
    }

    private fun enrollTotp(userId: Long, loginId: String): ByteArray {
        val enrollment = mfaService.enrollTotp(userId, loginId)
        val reference = mfaMethodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        val secret = secretStore.load(reference)
        mfaService.confirmTotp(userId, enrollment.methodId, Totp.code(secret, Instant.now()))
        return secret
    }

    /** 허용 구간(앞뒤 30초) 밖의 코드 */
    private fun wrongCode(secret: ByteArray) = Totp.code(secret, Instant.now().plusSeconds(600))

    private fun login(loginId: String, password: String, session: MockHttpSession = MockHttpSession()) =
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(session).with(csrf()))

    private fun auditActions(subjectId: Long): List<String> =
        jdbc.queryForList("SELECT action FROM audit_event WHERE target_subject_id = ? ORDER BY event_id", String::class.java, subjectId).filterNotNull()

    private fun events(subjectId: Long, type: String, result: String): Int =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM authentication_event WHERE subject_id = ? AND event_type = ? AND result = ?",
            Int::class.java, subjectId, type, result,
        ) ?: 0

    /** MockMvc 는 무효화된 세션을 재사용할 수 없으므로 같은 속성을 가진 새 세션으로 다음 요청을 보낸다 */
    private fun copy(from: MockHttpSession, to: MockHttpSession) {
        from.attributeNames.toList().forEach { to.setAttribute(it, from.getAttribute(it)) }
    }
}
