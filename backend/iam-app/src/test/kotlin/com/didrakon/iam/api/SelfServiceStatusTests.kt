package com.didrakon.iam.api

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.temporal.ChronoUnit

/** 본인 API(@SelfService)는 사용 중인 사람만 쓴다. 사용 중지된 사람의 남은 접근 토큰(최대 10분)으로 권한을 넘기지 못하게 한다 */
@AuthzTest
class SelfServiceStatusTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val userService: UserService,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
) {
    @Test
    fun `사용 중지된 사람의 토큰으로는 본인 API 를 쓸 수 없고 역할을 위임할 수도 없다`() {
        val admin = fixture.user("관리자")
        val adminRole = roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError()
        assignmentService.assignDirect(admin, adminRole)
        val accomplice = fixture.user("받는 사람")
        mockMvc.perform(get("/api/v1/me").with(token(admin))).andExpect(status().isOk)

        userService.changeStatus(admin, SubjectStatus.DISABLED)

        mockMvc.perform(get("/api/v1/me").with(token(admin))).andExpect(status().isForbidden)
        val now = Instant.now()
        mockMvc.perform(
            post("/api/v1/me/delegations").with(token(admin)).contentType(MediaType.APPLICATION_JSON).content(
                """{"delegateId":$accomplice,"roleId":$adminRole,"scopeId":${fixture.globalScopeId()},""" +
                    """"startTime":"$now","endTime":"${now.plus(30, ChronoUnit.DAYS)}","reason":"x"}""",
            ),
        ).andExpect(status().isForbidden)
    }

    private fun token(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
