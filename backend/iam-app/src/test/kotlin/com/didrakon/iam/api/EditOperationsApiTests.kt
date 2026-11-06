package com.didrakon.iam.api

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.policy.PolicyTargetRepository
import com.didrakon.iam.authz.policy.PolicyTargetSpec
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.governance.sod.RoleConflictRepository
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.jayway.jsonpath.JsonPath
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 정책 대상·직무 분리 규칙·소속 직무 정보 수정. 테스트마다 롤백된다 */
@AuthzTest
class EditOperationsApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val catalogService: AuthzCatalogService,
    private val policyService: PolicyService,
    private val versionService: PolicyVersionService,
    private val targetRepository: PolicyTargetRepository,
    private val conflictService: RoleConflictService,
    private val conflictRepository: RoleConflictRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val pdp: PolicyDecisionPoint,
    private val jdbc: JdbcTemplate,
) {
    // ---------- 정책 대상 ----------

    @Test
    fun `정책 대상을 바꾸면 다음 판정부터 새 대상에만 걸리고 감사 기록에 전후 대상이 남는다`() {
        val admin = globalAdmin()
        val first = fixture.resource().requireId()
        val second = fixture.resource().requireId()
        val userId = fixture.user()
        listOf(first, second).forEach { assignmentService.assignDirect(userId, fixture.roleAllowing(it).requireId()) }
        val policy = policyService.create(
            "P-${System.nanoTime()}", "해외 차단", PolicyType.SECURITY, PolicyEffect.DENY, listOf(PolicyTargetSpec(resourceId = first)),
        ).requireId()
        versionService.activate(
            versionService.createVersion(policy, listOf(RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.NE, "\"KR\""))).requireId(),
        )
        assertEquals(Decision.DENY, decide(userId, first))
        assertEquals(Decision.ALLOW, decide(userId, second))

        json(put("/api/v1/policies/$policy/targets"), admin, """{"targets":[{"resourceId":$second}]}""").andExpect(status().isOk)

        assertEquals(Decision.ALLOW, decide(userId, first))
        assertEquals(Decision.DENY, decide(userId, second))
        assertEquals(listOf(second), targetRepository.findByPolicyId(policy).map { it.resourceId })
        val (before, after) = auditValues("POLICY", policy, "UPDATE_TARGETS")
        assertEquals(listOf(first), JsonPath.read<List<Number>>(before, "$.targets[*].resourceId").map { it.toLong() })
        assertEquals(listOf(second), JsonPath.read<List<Number>>(after, "$.targets[*].resourceId").map { it.toLong() })
    }

    @Test
    fun `정책 대상은 만들 때와 같이 검사한다 - 비어 있거나 둘 이상 지정하면 거부`() {
        val admin = globalAdmin()
        val resource = fixture.resource().requireId()
        val role = fixture.role().requireId()
        val policy = policyService.create(
            "P-${System.nanoTime()}", "정책", PolicyType.SECURITY, PolicyEffect.DENY, listOf(PolicyTargetSpec(resourceId = resource)),
        ).requireId()

        json(put("/api/v1/policies/$policy/targets"), admin, """{"targets":[]}""").andExpect(status().is4xxClientError)
        json(put("/api/v1/policies/$policy/targets"), admin, """{"targets":[{"resourceId":$resource,"roleId":$role}]}""")
            .andExpect(status().is4xxClientError)
        assertEquals(listOf(resource), targetRepository.findByPolicyId(policy).map { it.resourceId })

        // 같은 대상으로 바꾸면 기록하지 않는다
        json(put("/api/v1/policies/$policy/targets"), admin, """{"targets":[{"resourceId":$resource}]}""").andExpect(status().isOk)
        assertEquals(0, auditCount("POLICY", policy, "UPDATE_TARGETS"))

        json(put("/api/v1/policies/$policy/targets"), admin, """{"targets":[{"resourceId":$resource},{"roleId":$role}]}""").andExpect(status().isOk)
        assertEquals(2, targetRepository.findByPolicyId(policy).size)
    }

    // ---------- 직무 분리 ----------

    @Test
    fun `직무 분리 규칙의 심각도·설명을 고치면 저장되고 감사 기록에 전후 값이 남는다 (역할 쌍은 그대로)`() {
        val admin = globalAdmin()
        val roleA = fixture.role().requireId()
        val roleB = fixture.role().requireId()
        val conflict = conflictService.define(roleA, roleB, RiskLevel.MEDIUM, "처음 설명").requireId()

        json(put("/api/v1/role-conflicts/$conflict"), admin, """{"severity":"CRITICAL","description":"고친 설명"}""").andExpect(status().isOk)

        val saved = conflictRepository.findById(conflict).orElseThrow()
        assertEquals(RiskLevel.CRITICAL, saved.severity)
        assertEquals("고친 설명", saved.description)
        assertEquals(setOf(roleA, roleB), setOf(saved.roleIdA, saved.roleIdB))
        val (before, after) = auditValues("ROLE_CONFLICT", conflict, "UPDATE")
        assertEquals("MEDIUM", JsonPath.read(before, "$.severity"))
        assertEquals("처음 설명", JsonPath.read(before, "$.description"))
        assertEquals("CRITICAL", JsonPath.read(after, "$.severity"))
        assertEquals("고친 설명", JsonPath.read(after, "$.description"))

        json(put("/api/v1/role-conflicts/$conflict"), admin, """{"severity":"CRITICAL","description":"  "}""").andExpect(status().isOk)
        assertNull(conflictRepository.findById(conflict).orElseThrow().description)
    }

    // ---------- 소속 직무 정보 ----------

    @Test
    fun `조직 단위 관리자는 범위 안 소속의 직위·직급·조직장 여부를 고치고 감사 기록이 남는다`() {
        val scopeOrg = fixture.org(OrgType.DIVISION)
        val childOrg = fixture.org(OrgType.TEAM, scopeOrg)
        val orgAdmin = orgAdmin(scopeOrg)
        val member = fixture.user().also { fixture.join(it, childOrg) }
        val membership = primaryMembership(member)

        json(put("/api/v1/memberships/$membership"), orgAdmin, """{"jobTitle":"팀장","jobGrade":"G5","isManager":true}""")
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.jobTitle").value("팀장"))
            .andExpect(jsonPath("$.data.isManager").value(true))

        val saved = membershipRepository.findById(membership).orElseThrow()
        assertEquals("팀장", saved.jobTitle)
        assertEquals("G5", saved.jobGrade)
        assertTrue(saved.isManager)
        assertEquals(childOrg, saved.orgId)
        val (before, after) = auditValues("SUBJECT_ORGANIZATION", membership, "UPDATE")
        assertEquals(false, JsonPath.read(before, "$.isManager"))
        assertEquals(true, JsonPath.read(after, "$.isManager"))
        assertEquals("팀장", JsonPath.read(after, "$.jobTitle"))
    }

    @Test
    fun `조직 단위 관리자는 범위 밖 소속과 다른 관리자의 소속을 고칠 수 없다`() {
        val scopeOrg = fixture.org(OrgType.DIVISION)
        val otherOrg = fixture.org(OrgType.DIVISION)
        val orgAdmin = orgAdmin(scopeOrg)
        val outsider = fixture.user().also { fixture.join(it, otherOrg) }
        val peer = orgAdmin(scopeOrg)
        val body = """{"jobTitle":"조직장","isManager":true}"""

        json(put("/api/v1/memberships/${primaryMembership(outsider)}"), orgAdmin, body).andExpect(status().isForbidden)
        json(put("/api/v1/memberships/${primaryMembership(peer)}"), orgAdmin, body).andExpect(status().isForbidden)
        assertFalse(membershipRepository.findById(primaryMembership(outsider)).orElseThrow().isManager)
        assertFalse(membershipRepository.findById(primaryMembership(peer)).orElseThrow().isManager)

        // 전체 관리자는 고칠 수 있다
        json(put("/api/v1/memberships/${primaryMembership(peer)}"), globalAdmin(), body).andExpect(status().isOk)
        assertTrue(membershipRepository.findById(primaryMembership(peer)).orElseThrow().isManager)
    }

    private fun primaryMembership(subjectId: Long): Long = membershipRepository.findActivePrimary(subjectId)?.requireId() ?: throw AssertionError("소속 없음")

    private fun decide(subjectId: Long, resourceId: Long) =
        pdp.decide(AuthorizationRequest(subjectId, resourceId, PermissionAction.READ, context = mapOf("country" to "US"))).decision

    private fun auditValues(resourceType: String, id: Long, action: String): Pair<String, String> = jdbc.queryForList(
        "SELECT before_value, after_value FROM audit_event WHERE resource_type = ? AND resource_id = ? AND action = ? ORDER BY event_id",
        resourceType, id.toString(), action,
    ).single().let { (it["before_value"] as String) to (it["after_value"] as String) }

    private fun auditCount(resourceType: String, id: Long, action: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM audit_event WHERE resource_type = ? AND resource_id = ? AND action = ?",
        Int::class.java, resourceType, id.toString(), action,
    ) ?: 0

    private fun orgAdmin(orgId: Long): Long = fixture.user("조직 관리자").also {
        fixture.join(it, orgId)
        val scope = catalogService.createScope("ORG-ADMIN-${System.nanoTime()}", "조직 범위", ScopeType.ORGANIZATION, orgId = orgId, includeDescendants = true)
        val role = roleRepository.findByRoleCode(IamBootstrap.ORG_ADMIN_ROLE)?.requireId() ?: throw AssertionError("IAM_ORG_ADMIN 역할 없음")
        assignmentService.assignDirect(it, role, scope.requireId())
    }

    @Test
    fun `관리 API MFA 정책은 콘솔 API 로 끄거나 대상·규칙을 바꿀 수 없다`() {
        val admin = globalAdmin()
        val policyId = jdbc.queryForObject("SELECT policy_id FROM policy WHERE policy_code = ?", Long::class.java, IamBootstrap.MFA_POLICY)
            ?: throw AssertionError("MFA 정책 없음")
        mockMvc.perform(post("/api/v1/policies/$policyId/deactivate").with(user(admin))).andExpect(status().isConflict)
        json(put("/api/v1/policies/$policyId/targets"), admin, """{"targets":[{"roleId":1}]}""").andExpect(status().isConflict)
        json(post("/api/v1/policies/$policyId/versions"), admin, """{"rules":[]}""").andExpect(status().isConflict)
        // 예외도 그 대상에게 정책을 끄는 것과 같다
        json(post("/api/v1/policies/$policyId/exceptions"), admin, """{"subjectId":$admin,"reason":"x"}""").andExpect(status().isConflict)
    }

    @Test
    fun `정책 예외를 추가하면 감사 기록에 남는다`() {
        val admin = globalAdmin()
        val policy = policyService.create(
            "P-${System.nanoTime()}", "정책", PolicyType.SECURITY, PolicyEffect.DENY, listOf(PolicyTargetSpec(resourceId = fixture.resource().requireId())),
        ).requireId()

        json(post("/api/v1/policies/$policy/exceptions"), admin, """{"subjectId":$admin,"reason":"점검"}""").andExpect(status().isCreated)

        val actions = jdbc.queryForList("SELECT action FROM audit_event WHERE resource_type = 'POLICY' AND resource_id = ?", String::class.java, policy.toString())
        assertEquals(listOf("ADD_EXCEPTION"), actions)
    }

    private fun globalAdmin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun json(builder: MockHttpServletRequestBuilder, subjectId: Long, body: String) =
        mockMvc.perform(builder.with(user(subjectId)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
