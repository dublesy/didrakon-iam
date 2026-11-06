package com.didrakon.iam.api

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.risk.RiskContext
import com.didrakon.iam.risk.RiskEngine
import com.didrakon.iam.risk.RiskType
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals

/** 위험 정책 관리 API. 테스트마다 롤백된다 */
@AuthzTest
class RiskApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val riskEngine: RiskEngine,
    private val jdbc: JdbcTemplate,
) {
    @Test
    fun `정책을 추가·수정·끄면 엔진이 바로 따르고 변경마다 감사 기록이 남는다`() {
        val admin = admin()
        val subject = fixture.user()
        jdbc.update("UPDATE risk_policy SET is_active = FALSE")

        val created = mockMvc.perform(
            post("/api/v1/risk-policies").with(user(admin)).contentType(MediaType.APPLICATION_JSON).content(
                """{"riskType":"LOGIN","policyName":"새 기기","conditionExpression":"{ \"signal\": \"NEW_DEVICE\" }","riskScore":30,"action":"CHALLENGE"}""",
            ),
        ).andExpect(status().isCreated)
            .andExpect(jsonPath("$.data.conditionExpression").value("""{"signal":"NEW_DEVICE"}"""))
            .andReturn().response.contentAsString
        val policyId = Regex("\"riskPolicyId\":(\\d+)").find(created)?.groupValues?.get(1) ?: throw AssertionError(created)
        assertEquals(30, score(subject))

        mockMvc.perform(
            put("/api/v1/risk-policies/$policyId").with(user(admin)).contentType(MediaType.APPLICATION_JSON).content(
                """{"policyName":"새 기기","conditionExpression":"{\"signal\":\"NEW_DEVICE\"}","riskScore":45,"action":"DENY"}""",
            ),
        ).andExpect(status().isOk).andExpect(jsonPath("$.data.riskScore").value(45))
        assertEquals(45, score(subject))

        mockMvc.perform(post("/api/v1/risk-policies/$policyId/deactivate").with(user(admin)))
            .andExpect(jsonPath("$.data.isActive").value(false))
        assertEquals(0, score(subject))

        val actions = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'RISK_POLICY' AND resource_id = ? ORDER BY event_id",
            String::class.java, policyId,
        )
        assertEquals(listOf("CREATE", "UPDATE", "DEACTIVATE"), actions)
    }

    @Test
    fun `엔진이 읽을 수 없는 조건은 저장하지 않는다`() {
        val admin = admin()
        listOf(
            """not json""",
            """{\"signal\":\"UNKNOWN\"}""",
            """{\"signal\":\"UNUSUAL_TIME\",\"from\":\"7시\"}""",
            """{\"signal\":\"MASS_ACCESS\",\"threshold\":0}""",
            """{\"signal\":\"FOREIGN_IP\",\"allowedCountries\":\"KR\"}""",
        ).forEach { condition ->
            mockMvc.perform(
                post("/api/v1/risk-policies").with(user(admin)).contentType(MediaType.APPLICATION_JSON).content(
                    """{"riskType":"LOGIN","policyName":"잘못된 조건","conditionExpression":"$condition","riskScore":10,"action":"ALLOW"}""",
                ),
            ).andExpect(status().is4xxClientError)
        }
    }

    @Test
    fun `사용자의 최근 위험 평가와 신호를 조회한다`() {
        val admin = admin()
        val subject = fixture.user()
        // 기본 정책의 '평소와 다른 시간'(07~22시 밖) 신호는 실행 시각에 따라 붙으므로 끄고 본다
        jdbc.update("UPDATE risk_policy SET is_active = FALSE WHERE condition_expression LIKE '%UNUSUAL_TIME%'")
        riskEngine.assess(RiskContext(subject, RiskType.LOGIN, knownDevice = false))

        mockMvc.perform(get("/api/v1/subjects/$subject/risk").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.assessments[0].riskScore").value(20))
            .andExpect(jsonPath("$.data.signals[0].signalType").value("NEW_DEVICE"))
    }

    @Test
    fun `권한이 없으면 위험 정책을 볼 수 없다`() {
        mockMvc.perform(get("/api/v1/risk-policies").with(user(fixture.user()))).andExpect(status().isForbidden)
    }

    private fun score(subjectId: Long) = riskEngine.evaluate(RiskContext(subjectId, RiskType.LOGIN, knownDevice = false)).score

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
