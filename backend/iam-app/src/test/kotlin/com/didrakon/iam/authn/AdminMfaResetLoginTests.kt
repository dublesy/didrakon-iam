package com.didrakon.iam.authn

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant

/** 관리자의 2단계 인증 초기화가 실제 로그인에 반영되는지. 로그인은 커밋된 데이터로 확인하므로 롤백하지 않는다 */
@IntegrationTest
class AdminMfaResetLoginTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val accountService: LocalAccountService,
    private val mfaService: MfaService,
    private val methodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val assignmentService: RoleAssignmentService,
    private val roleRepository: RoleRepository,
) {
    private val password = "correct-horse-battery"

    @Test
    fun `관리자가 인증 앱을 초기화하면 다음 로그인은 MFA 화면으로 가지 않는다`() {
        val admin = fixture.user("관리자").also {
            assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
        }
        val userId = fixture.user()
        val loginId = "reset${System.nanoTime()}"
        accountService.createAccount(userId, loginId, password)
        val enrollment = mfaService.enrollTotp(userId, loginId)
        val reference = methodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        mfaService.confirmTotp(userId, enrollment.methodId, Totp.code(secretStore.load(reference), Instant.now()))

        login(loginId).andExpect(redirectedUrl("/login/mfa"))

        mockMvc.perform(
            delete("/api/v1/subjects/$userId/mfa/${enrollment.methodId}")
                .with(jwt().jwt { it.subject(admin.toString()).claim("amr", listOf("pwd", "otp")) }),
        ).andExpect(status().isOk)

        login(loginId).andExpect(redirectedUrl("/"))
    }

    private fun login(loginId: String) =
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(MockHttpSession()).with(csrf()))
}
