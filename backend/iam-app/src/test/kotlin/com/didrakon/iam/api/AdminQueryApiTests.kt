package com.didrakon.iam.api

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.policy.PolicyTargetSpec
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import org.hamcrest.Matchers.hasItem
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status

/** 관리 콘솔이 쓰는 목록·상세 조회 API */
@AuthzTest
class AdminQueryApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val userRepository: UserRepository,
    private val policyService: PolicyService,
    private val versionService: PolicyVersionService,
    private val conflictService: RoleConflictService,
) {
    @Test
    fun `사용자는 이름·사번으로 검색하고 페이지 정보를 준다`() {
        val admin = admin()
        val marker = "검색-${System.nanoTime()}"
        repeat(3) { userRepository.save(User("E-$marker-$it", "$marker 직원")) }

        mockMvc.perform(get("/api/v1/users").param("q", marker).param("size", "2").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.items.length()").value(2))
            .andExpect(jsonPath("$.data.total").value(3))
            .andExpect(jsonPath("$.data.page").value(0))
    }

    @Test
    fun `조직 목록·구성원과 subject 이름을 조회한다`() {
        val admin = admin()
        val company = fixture.org(OrgType.COMPANY)
        val member = fixture.user("구성원").also { fixture.join(it, company) }

        mockMvc.perform(get("/api/v1/organizations").with(user(admin)))
            .andExpect(jsonPath("$.data[*].orgId", hasItem(company.toInt())))
        mockMvc.perform(get("/api/v1/organizations/$company/members").with(user(admin)))
            .andExpect(jsonPath("$.data[0].subjectId").value(member))
        mockMvc.perform(get("/api/v1/subjects/names").param("ids", "$member").with(user(admin)))
            .andExpect(jsonPath("$.data[0].subjectName").value("구성원"))
    }

    @Test
    fun `역할 상세는 담긴 권한과 scope 를 함께 준다`() {
        val admin = admin()
        val role = fixture.roleAllowing(fixture.resource().requireId())

        mockMvc.perform(get("/api/v1/roles/${role.requireId()}").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.role.roleCode").value(role.roleCode))
            .andExpect(jsonPath("$.data.permissions[0].permission.action").value("READ"))
            .andExpect(jsonPath("$.data.permissions[0].scope.scopeCode").value("GLOBAL"))
    }

    @Test
    fun `정책 상세는 대상·버전별 규칙을 최신 버전부터 준다`() {
        val admin = admin()
        val policy = policyService.create("P-${System.nanoTime()}", "정책", PolicyType.SECURITY, PolicyEffect.DENY, listOf(PolicyTargetSpec(roleId = fixture.role().requireId())))
        versionService.createVersion(policy.requireId(), listOf(RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.NE, "\"KR\"")))
        versionService.createVersion(policy.requireId(), emptyList())

        mockMvc.perform(get("/api/v1/policies/${policy.requireId()}").with(user(admin)))
            .andExpect(jsonPath("$.data.targets.length()").value(1))
            .andExpect(jsonPath("$.data.versions[0].version").value(2))
            .andExpect(jsonPath("$.data.versions[1].rules[0].attributeName").value("country"))
    }

    @Test
    fun `역할 충돌 목록은 승인된 예외를 함께 준다`() {
        val admin = admin()
        val conflict = conflictService.define(fixture.role().requireId(), fixture.role().requireId(), RiskLevel.HIGH)
        conflictService.grantException(conflict.requireId(), fixture.user(), admin, "한시 허용", null)

        mockMvc.perform(get("/api/v1/role-conflicts").with(user(admin)))
            .andExpect(jsonPath("$.data[?(@.conflictId == ${conflict.requireId()})].exceptions[0].reason").value("한시 허용"))
    }

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
