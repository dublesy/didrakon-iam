package com.didrakon.iam.api

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.api.support.SelfService
import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyRuleRepository
import com.didrakon.iam.authz.policy.PolicyVersionRepository
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.PolicyVersionStatus
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.subject.Environment
import com.didrakon.iam.identity.subject.ServiceAccount
import com.didrakon.iam.identity.subject.SubjectRepository
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.annotation.Qualifier
import org.springframework.boot.DefaultApplicationArguments
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.header
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.method.HandlerMethod
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping
import kotlin.test.assertEquals

@AuthzTest
class ApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val userService: com.didrakon.iam.identity.subject.UserService,
    private val subjectRepository: SubjectRepository,
    private val apiKeyService: ApiKeyService,
    private val jdbc: JdbcTemplate,
    @Qualifier("requestMappingHandlerMapping") private val handlerMapping: RequestMappingHandlerMapping,
    private val bootstrap: IamBootstrap,
    private val policyRepository: PolicyRepository,
    private val policyVersionService: PolicyVersionService,
    private val policyVersionRepository: PolicyVersionRepository,
    private val policyRuleRepository: PolicyRuleRepository,
) {
    @Test
    fun `모든 api 핸들러에는 인가 애노테이션이 있다`() {
        val missing = handlerMapping.handlerMethods.filter { (info, method) ->
            info.patternValues.any { it.startsWith("/api/") } && !method.isAuthorized()
        }.map { (info, _) -> info.toString() }

        assertEquals(emptyList(), missing)
    }

    @Test
    fun `토큰이 없으면 공통 오류 형식으로 401 을 준다`() {
        mockMvc.perform(get("/api/v1/me"))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.success").value(false))
            .andExpect(jsonPath("$.error.code").value("UNAUTHENTICATED"))
    }

    @Test
    fun `관리 권한이 없는 사용자는 403 을 받는다`() {
        mockMvc.perform(json(post("/api/v1/organizations"), """{"orgCode":"X","orgName":"X","orgType":"COMPANY"}""").with(user(fixture.user())))
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error.code").value("FORBIDDEN"))
    }

    @Test
    fun `IAM 관리자는 MFA 를 거친 토큰으로만 관리 API 를 쓸 수 있다`() {
        val admin = admin()
        val body = """{"orgCode":"CO-${System.nanoTime()}","orgName":"법인","orgType":"COMPANY"}"""

        mockMvc.perform(json(post("/api/v1/organizations"), body).with(user(admin, amr = listOf("pwd"))))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))

        mockMvc.perform(json(post("/api/v1/organizations"), body).with(user(admin)))
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.success").value(true))
            .andExpect(jsonPath("$.data.orgType").value("COMPANY"))
    }

    @Test
    fun `패스키 로그인(amr hwk) 토큰도 MFA 를 거친 것으로 보고 관리 API 를 허용한다`() {
        val body = """{"orgCode":"CO-${System.nanoTime()}","orgName":"법인","orgType":"COMPANY"}"""

        mockMvc.perform(json(post("/api/v1/organizations"), body).with(user(admin(), amr = listOf("hwk", "user"))))
            .andExpect(status().isCreated)
    }

    @Test
    fun `패스키 이전에 만든 관리 API MFA 정책은 기동할 때 hwk 도 인정하는 새 버전으로 바뀐다`() {
        val policyId = policyRepository.findAll().single { it.policyCode == IamBootstrap.MFA_POLICY }.requireId()
        val otpOnly = policyVersionService.createVersion(
            policyId, listOf(RuleSpec(1, AttributeSource.SESSION, "amr", RuleOperator.NOT_IN, "[\"otp\"]")), changeReason = "패스키 이전",
        )
        policyVersionService.activate(otpOnly.requireId())
        val admin = admin()
        val body = { """{"orgCode":"CO-${System.nanoTime()}","orgName":"법인","orgType":"COMPANY"}""" }
        mockMvc.perform(json(post("/api/v1/organizations"), body()).with(user(admin, amr = listOf("hwk", "user"))))
            .andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))

        bootstrap.run(DefaultApplicationArguments())

        val active = policyVersionRepository.findByPolicyIdAndStatus(policyId, PolicyVersionStatus.ACTIVE).single()
        assertEquals(listOf("[\"otp\",\"hwk\"]"), policyRuleRepository.findByPolicyVersionIdIn(listOf(active.requireId())).map { it.attributeValue })
        mockMvc.perform(json(post("/api/v1/organizations"), body()).with(user(admin, amr = listOf("hwk", "user"))))
            .andExpect(status().isCreated)
        mockMvc.perform(json(post("/api/v1/organizations"), body()).with(user(admin, amr = listOf("pwd"))))
            .andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))
    }

    @Test
    fun `요청의 행위자와 trace ID 가 감사 기록에 남고 trace ID 는 응답 헤더로 돌아온다`() {
        val admin = admin()
        val target = fixture.user()
        val roleId = fixture.role().requireId()

        mockMvc.perform(
            json(post("/api/v1/assignments"), """{"subjectId":$target,"roleId":$roleId,"reason":"업무"}""")
                .header("X-Trace-Id", "trace-api-1").with(user(admin)),
        ).andExpect(status().isCreated).andExpect(header().string("X-Trace-Id", "trace-api-1"))

        val audited = jdbc.queryForMap(
            "SELECT actor_subject_id, action FROM audit_event WHERE trace_id = 'trace-api-1' AND event_type = 'ROLE_CHANGE'",
        )
        assertEquals(admin, (audited["actor_subject_id"] as Number).toLong())
        assertEquals("ASSIGN", audited["action"])
    }

    @Test
    fun `감사자는 조회만 할 수 있다`() {
        val auditor = fixture.user().also { assign(it, IamBootstrap.AUDITOR_ROLE) }
        val target = fixture.user()

        mockMvc.perform(get("/api/v1/users/$target").with(user(auditor))).andExpect(status().isOk)
        mockMvc.perform(json(post("/api/v1/users"), """{"empNo":"E-${System.nanoTime()}","name":"새 직원"}""").with(user(auditor)))
            .andExpect(status().isForbidden)
    }

    @Test
    fun `입력 검증·업무 규칙·없는 대상은 각각 400·409·404 로 응답한다`() {
        val admin = admin()

        mockMvc.perform(json(post("/api/v1/users"), """{"empNo":"","name":"이름"}""").with(user(admin)))
            .andExpect(status().isBadRequest)
            .andExpect(jsonPath("$.error.code").value("VALIDATION"))
            .andExpect(jsonPath("$.error.fields.empNo").exists())

        val target = fixture.user()
        val company = fixture.org(OrgType.COMPANY)
        val join = """{"subjectId":$target,"orgId":$company,"membershipType":"PRIMARY"}"""
        mockMvc.perform(json(post("/api/v1/memberships"), join).with(user(admin))).andExpect(status().isCreated)
        mockMvc.perform(json(post("/api/v1/memberships"), join).with(user(admin)))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error.code").value("BUSINESS_RULE"))

        mockMvc.perform(get("/api/v1/users/999999999").with(user(admin)))
            .andExpect(status().isNotFound)
            .andExpect(jsonPath("$.error.code").value("NOT_FOUND"))
    }

    @Test
    fun `권한 판정 API 는 판정 scope 가 있는 클라이언트 토큰으로 부를 수 있다`() {
        val resource = fixture.resource()
        val userId = fixture.user().also { assignmentService.assignDirect(it, fixture.roleAllowing(resource.requireId()).requireId()) }
        val body = """{"subjectId":$userId,"resourceId":${resource.requireId()},"action":"READ"}"""

        mockMvc.perform(json(post("/api/v1/authz/check"), body).with(client(ApiResources.AUTHZ_CHECK_SCOPE)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.decision").value("ALLOW"))
        mockMvc.perform(json(post("/api/v1/authz/check"), body).with(client("other.scope")))
            .andExpect(status().isForbidden)
            .andExpect(jsonPath("$.error.code").value("SUBJECT_REQUIRED"))
    }

    @Test
    fun `판정 API 역할을 가진 서비스 계정은 API 키로 부를 수 있다`() {
        val owner = fixture.user()
        val service = subjectRepository.save(ServiceAccount("order-api", owner, Environment.PROD)).requireId()
        assign(service, IamBootstrap.AUTHZ_CLIENT_ROLE)
        val key = apiKeyService.issue(service, "order-api 판정").rawKey
        val body = """{"subjectId":$owner,"resourceId":${fixture.resource().requireId()},"action":"READ"}"""

        mockMvc.perform(json(post("/api/v1/authz/check"), body).header("X-API-Key", key))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.decision").value("DENY"))
        mockMvc.perform(json(post("/api/v1/authz/check"), body).header("X-API-Key", "iam_invalid"))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error.code").value("INVALID_API_KEY"))
    }

    @Test
    fun `본인 API 는 관리 권한 없이 토큰의 subject 로 동작한다`() {
        val userId = fixture.user()
        val roleId = fixture.role().requireId()

        mockMvc.perform(get("/api/v1/me").with(user(userId)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.subjectId").value(userId))

        val start = java.time.Instant.now()
        mockMvc.perform(
            json(
                post("/api/v1/me/access-requests"),
                """{"roleId":$roleId,"reason":"점검","requestedStart":"$start","requestedEnd":"${start.plusSeconds(3600)}"}""",
            ).with(user(userId)),
        ).andExpect(status().isCreated).andExpect(jsonPath("$.data.subjectId").value(userId))
    }

    @Test
    fun `계정 연결 조회는 사번·이메일로 subject ID 를 찾고 이메일은 대소문자를 무시하며 일반 사용자는 쓸 수 없다`() {
        val admin = admin()
        val first = fixture.user("연결1")
        val second = fixture.user("연결2")
        userService.update(second, "연결2", "link.$second@example.com", null, null)
        val empNo = jdbc.queryForObject("SELECT emp_no FROM user WHERE subject_id = ?", String::class.java, first)
        val body = """{"empNos":["$empNo","NO-SUCH"],"emails":["LINK.$second@EXAMPLE.COM"]}"""

        mockMvc.perform(json(post("/api/v1/users/lookup").with(user(admin)), body))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[0].matchedBy").value("EMP_NO"))
            .andExpect(jsonPath("$.data[0].matches[0].subjectId").value(first))
            .andExpect(jsonPath("$.data[1].key").value("NO-SUCH"))
            .andExpect(jsonPath("$.data[1].matches.length()").value(0))
            .andExpect(jsonPath("$.data[2].matchedBy").value("EMAIL"))
            .andExpect(jsonPath("$.data[2].matches[0].subjectId").value(second))

        mockMvc.perform(json(post("/api/v1/users/lookup").with(user(fixture.user())), body)).andExpect(status().isForbidden)
    }

    private fun HandlerMethod.isAuthorized() =
        hasMethodAnnotation(RequiresPermission::class.java) || hasMethodAnnotation(SelfService::class.java)

    private fun admin(): Long = fixture.user("관리자").also { assign(it, IamBootstrap.ADMIN_ROLE) }

    private fun assign(subjectId: Long, roleCode: String) {
        val role = roleRepository.findByRoleCode(roleCode) ?: throw AssertionError("$roleCode 역할 없음")
        assignmentService.assignDirect(subjectId, role.requireId())
    }

    /** IAM 이 발급한 사용자 토큰과 같은 모양 (sub = subject ID, amr) */
    private fun user(subjectId: Long, amr: List<String> = listOf("pwd", "otp")) =
        jwt().jwt { it.subject(subjectId.toString()).claim("amr", amr) }

    /** client credentials 토큰 (sub = client_id) */
    private fun client(scope: String) =
        jwt().jwt { it.subject("batch-client") }.authorities(SimpleGrantedAuthority("SCOPE_$scope"))

    private fun json(builder: MockHttpServletRequestBuilder, body: String) = builder.contentType(MediaType.APPLICATION_JSON).content(body)
}
