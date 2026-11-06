package com.didrakon.iam.api

import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.temporal.ChronoUnit

/** 역할 위임은 로그인한 본인만, 관리 권한이 있는 역할은 MFA 로그인으로만 한다 (관리 API MFA 정책을 위임으로 돌아가지 못하게) */
@AuthzTest
class MeDelegationApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val apiKeyService: ApiKeyService,
) {
    @Test
    fun `관리자의 API 키나 비밀번호만 거친 토큰으로는 관리 역할을 위임할 수 없다`() {
        val admin = fixture.user("관리자")
        val adminRole = roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError()
        assignmentService.assignDirect(admin, adminRole)
        val accomplice = fixture.user("받는 사람")
        val apiKey = apiKeyService.issue(admin, "배치").rawKey

        mockMvc.perform(delegate(adminRole, accomplice).header("X-API-Key", apiKey))
            .andExpect(status().isForbidden).andExpect(jsonPath("$.error.code").value("INTERACTIVE_LOGIN_REQUIRED"))
        mockMvc.perform(delegate(adminRole, accomplice).with(token(admin, "pwd")))
            .andExpect(status().isUnauthorized).andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))
        mockMvc.perform(delegate(adminRole, accomplice).with(token(admin, "pwd", "otp"))).andExpect(status().isCreated)
    }

    @Test
    fun `관리 권한이 없는 역할은 비밀번호 로그인으로도 위임할 수 있다`() {
        val owner = fixture.user("업무 담당")
        val role = fixture.role().requireId()
        assignmentService.assignDirect(owner, role)
        val delegate = fixture.user("대리인")

        mockMvc.perform(delegate(role, delegate).with(token(owner, "pwd"))).andExpect(status().isCreated)
    }

    private fun delegate(roleId: Long, delegateId: Long): MockHttpServletRequestBuilder {
        val now = Instant.now()
        return post("/api/v1/me/delegations").contentType(MediaType.APPLICATION_JSON).content(
            """{"delegateId":$delegateId,"roleId":$roleId,"scopeId":${fixture.globalScopeId()},""" +
                """"startTime":"$now","endTime":"${now.plus(7, ChronoUnit.DAYS)}","reason":"휴가"}""",
        )
    }

    private fun token(subjectId: Long, vararg amr: String) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", amr.toList()) }
}
