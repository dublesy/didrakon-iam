package com.didrakon.iam.authn

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.login.PasswordResetService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.provider.Identity
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.hamcrest.Matchers.containsString
import java.time.Instant
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 셀프 비밀번호 재설정(인증 앱 코드)과 관리자 잠금 해제. 인증 이벤트가 바로 커밋되므로 롤백하지 않는다 */
@IntegrationTest
class PasswordResetTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val accountService: LocalAccountService,
    private val mfaService: MfaService,
    private val mfaMethodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val userService: UserService,
    private val assignmentService: RoleAssignmentService,
    private val roleRepository: RoleRepository,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
    private val resetService: PasswordResetService,
) {
    private val password = "correct-horse-battery"

    @Test
    fun `잠긴 계정도 인증 앱 코드로 본인을 확인하면 새 비밀번호를 정하고 잠금이 풀린다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        lock(loginId)
        mockMvc.perform(get("/login")).andExpect(content().string(containsString("/login/forgot")))
        mockMvc.perform(get("/login/forgot")).andExpect(status().isOk)
        val session = MockHttpSession()

        forgot(loginId, Totp.code(secret, Instant.now().plusSeconds(30)), session).andExpect(redirectedUrl("/login/password"))
        mockMvc.perform(post("/login/password").param("newPassword", "brand-new-pass-1").param("confirmPassword", "brand-new-pass-1").session(session).with(csrf()))
            .andExpect(redirectedUrl("/login?changed"))

        val credential = accountService.findCredential(loginId) ?: throw AssertionError()
        assertFalse(credential.isLockedAt(Instant.now()))
        assertEquals(0, credential.failedAttemptCount)
        // TOTP 를 등록한 계정이라 비밀번호 다음 MFA 단계로 간다
        login(loginId, "brand-new-pass-1").andExpect(redirectedUrl("/login/mfa"))
        assertEquals(1, resetEvents(userId, "SUCCESS", "PASSWORD_RESET_OK"))
        assertTrue("PASSWORD_RESET_SUCCESS" in auditActions(userId))
    }

    @Test
    fun `틀린 코드, 없는 로그인 ID, 인증 앱이 없는 계정은 모두 같은 응답이다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        val (noTotpUserId, noTotpLoginId) = account()

        forgot(loginId, wrongCode(secret)).andExpect(redirectedUrl("/login/forgot?error"))
        forgot("nobody${System.nanoTime()}", "123456").andExpect(redirectedUrl("/login/forgot?error"))
        forgot(noTotpLoginId, "123456").andExpect(redirectedUrl("/login/forgot?error"))

        val page = mockMvc.perform(get("/login/forgot?error")).andReturn().response.getContentAsString(Charsets.UTF_8)
        assertTrue("로그인 ID 또는 인증 코드가 맞지 않습니다. 인증 앱을 등록하지 않았다면 관리자에게 문의하세요." in page)
        assertEquals(1, resetEvents(userId, "FAILURE", "PASSWORD_RESET_FAILED"))
        assertEquals(1, resetEvents(noTotpUserId, "FAILURE", "PASSWORD_RESET_FAILED"))
        assertEquals(listOf("PASSWORD_RESET_FAILURE"), auditActions(userId))
        // 재설정 실패는 로그인 잠금 횟수에 넣지 않는다
        assertEquals(0, accountService.findCredential(loginId)?.failedAttemptCount)
    }

    @Test
    fun `한 시간에 5번 틀리면 맞는 코드로도 재설정할 수 없다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        repeat(5) { forgot(loginId, wrongCode(secret)).andExpect(redirectedUrl("/login/forgot?error")) }
        val session = MockHttpSession()

        forgot(loginId, Totp.code(secret, Instant.now().plusSeconds(30)), session).andExpect(redirectedUrl("/login/forgot?error"))

        mockMvc.perform(get("/login/password").session(session)).andExpect(redirectedUrl("/login"))
        assertEquals(1, resetEvents(userId, "FAILURE", "PASSWORD_RESET_LIMITED"))
        assertEquals(0, resetEvents(userId, "SUCCESS", "PASSWORD_RESET_OK"))
    }

    @Test
    fun `사용 중지된 사용자는 재설정할 수 없다`() {
        val (userId, loginId) = account()
        val secret = enrollTotp(userId, loginId)
        userService.changeStatus(userId, SubjectStatus.DISABLED)
        val session = MockHttpSession()

        forgot(loginId, Totp.code(secret, Instant.now().plusSeconds(30)), session).andExpect(redirectedUrl("/login/forgot?error"))

        mockMvc.perform(get("/login/password").session(session)).andExpect(redirectedUrl("/login"))
    }

    @Test
    fun `관리자가 잠금을 풀면 비밀번호는 그대로 로그인되고 감사 기록이 남는다`() {
        val admin = admin()
        val (userId, loginId) = account()
        lock(loginId)
        mockMvc.perform(get("/api/v1/users/$userId/credential").with(user(admin)))
            .andExpect(jsonPath("$.data.locked").value(true))
            .andExpect(jsonPath("$.data.lockedUntil").isNotEmpty)

        mockMvc.perform(post("/api/v1/users/$userId/unlock").with(user(admin))).andExpect(status().isOk)

        mockMvc.perform(get("/api/v1/users/$userId/credential").with(user(admin)))
            .andExpect(jsonPath("$.data.locked").value(false))
            .andExpect(jsonPath("$.data.lockedUntil").doesNotExist())
        login(loginId, password).andExpect(redirectedUrl("/"))
        val audit = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'USER' AND resource_id = ? AND action = 'UNLOCK'", String::class.java, userId.toString(),
        )
        assertEquals(1, audit.size)
    }

    @Test
    fun `로그인 계정이 없는 사용자는 상태가 비어 있고 잠금 해제는 찾을 수 없다`() {
        val admin = admin()
        val userId = fixture.user()

        mockMvc.perform(get("/api/v1/users/$userId/credential").with(user(admin))).andExpect(jsonPath("$.data").doesNotExist())
        mockMvc.perform(post("/api/v1/users/$userId/unlock").with(user(admin))).andExpect(status().isNotFound)
    }

    @Test
    fun `동시에 보낸 틀린 코드도 한 시간에 5번까지만 시도된다`() {
        val (userId, loginId) = account()
        val wrong = wrongCode(enrollTotp(userId, loginId))
        val pool = Executors.newFixedThreadPool(8)
        val start = CountDownLatch(1)
        val attempts = (1..15).map { i -> pool.submit<Identity?> { start.await(); resetService.verify(loginId, wrong, "10.0.0.$i", null) } }
        start.countDown()
        attempts.forEach { it.get(30, TimeUnit.SECONDS) }
        pool.shutdown()

        assertEquals(5, resetEvents(userId, "FAILURE", "PASSWORD_RESET_FAILED"))
        assertEquals(10, resetEvents(userId, "FAILURE", "PASSWORD_RESET_LIMITED"))
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

    private fun lock(loginId: String) {
        repeat(5) { login(loginId, "wrong-password-0") }
        assertTrue(accountService.findCredential(loginId)?.isLockedAt(Instant.now()) ?: false)
    }

    /** 허용 구간(앞뒤 30초) 밖의 코드 */
    private fun wrongCode(secret: ByteArray) = Totp.code(secret, Instant.now().plusSeconds(600))

    private fun forgot(loginId: String, code: String, session: MockHttpSession = MockHttpSession()) =
        mockMvc.perform(post("/login/forgot").param("loginId", loginId).param("code", code).session(session).with(csrf()))

    private fun login(loginId: String, password: String) =
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).with(csrf()))

    private fun resetEvents(subjectId: Long, result: String, reason: String): Int =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM authentication_event WHERE subject_id = ? AND event_type = 'PASSWORD_CHANGE' AND result = ? AND failure_reason = ?",
            Int::class.java, subjectId, result, reason,
        ) ?: 0

    private fun auditActions(subjectId: Long): List<String> =
        jdbc.queryForList("SELECT action FROM audit_event WHERE target_subject_id = ? ORDER BY event_id", String::class.java, subjectId).filterNotNull()

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
