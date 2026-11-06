package com.didrakon.iam.api

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.OrganizationRole
import com.didrakon.iam.authz.assignment.OrganizationRoleRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.config.UserTokenClaimsProvider
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserRepository
import com.jayway.jsonpath.JsonPath
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 조직 단위 관리자(IAM_ORG_ADMIN + ORGANIZATION 범위)와 외부 사용자. 테스트마다 롤백된다 */
@AuthzTest
class OrgAdminApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val catalogService: AuthzCatalogService,
    private val userRepository: UserRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val claimsProvider: UserTokenClaimsProvider,
    private val permissionRepository: PermissionRepository,
    private val authorizer: AdminAuthorizer,
    private val organizationRoleRepository: OrganizationRoleRepository,
) {
    /** 범위 조직(scopeOrg) 아래 하위 조직(childOrg), 범위 밖 조직(otherOrg) */
    private inner class World {
        val scopeOrg = fixture.org(OrgType.DIVISION)
        val childOrg = fixture.org(OrgType.TEAM, scopeOrg)
        val otherOrg = fixture.org(OrgType.DIVISION)
        val orgAdmin = orgAdmin(scopeOrg)
        val userIn = member(scopeOrg)
        val userChild = member(childOrg)
        val userOut = member(otherOrg)
    }

    @Test
    fun `조직 단위 관리자는 범위 안(하위 조직 포함) 사용자를 조회·수정·사용 중지하고 범위 밖은 거부된다`() {
        val w = World()

        listOf(w.userIn, w.userChild).forEach { target ->
            mockMvc.perform(get("/api/v1/users/$target").with(user(w.orgAdmin))).andExpect(status().isOk)
            json(put("/api/v1/users/$target"), w.orgAdmin, """{"name":"고친 이름"}""").andExpect(status().isOk)
            mockMvc.perform(post("/api/v1/users/$target/deactivate").with(user(w.orgAdmin))).andExpect(status().isOk)
            mockMvc.perform(get("/api/v1/subjects/$target/sessions").with(user(w.orgAdmin))).andExpect(status().isOk)
        }
        assertEquals(SubjectStatus.DISABLED, userRepository.findById(w.userChild).orElseThrow().status)

        mockMvc.perform(get("/api/v1/users/${w.userOut}").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        json(put("/api/v1/users/${w.userOut}"), w.orgAdmin, """{"name":"고친 이름"}""").andExpect(status().isForbidden)
        mockMvc.perform(post("/api/v1/users/${w.userOut}/deactivate").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/subjects/${w.userOut}/sessions").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/organizations/${w.otherOrg}/members").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/organizations/${w.scopeOrg}/members").with(user(w.orgAdmin))).andExpect(status().isOk)
        assertEquals(SubjectStatus.ACTIVE, userRepository.findById(w.userOut).orElseThrow().status)
    }

    @Test
    fun `조직 단위 관리자도 MFA 를 거쳐야 한다`() {
        val w = World()
        mockMvc.perform(get("/api/v1/users/${w.userIn}").with(jwt().jwt { it.subject(w.orgAdmin.toString()).claim("amr", listOf("pwd")) }))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))
    }

    @Test
    fun `목록은 조직 단위 관리자에게 범위 안만, 전체 관리자에게는 모두 보인다`() {
        val w = World()
        val admin = globalAdmin()

        val scopedUsers = ids(mockMvc.perform(get("/api/v1/users?size=100").with(user(w.orgAdmin))), "$.data.items[*].subjectId")
        assertEquals(setOf(w.orgAdmin, w.userIn, w.userChild), scopedUsers.toSet())
        val scopedOrgs = ids(mockMvc.perform(get("/api/v1/organizations").with(user(w.orgAdmin))), "$.data[*].orgId")
        assertEquals(setOf(w.scopeOrg, w.childOrg), scopedOrgs.toSet())
        val names = ids(mockMvc.perform(get("/api/v1/subjects/names?ids=${w.userIn},${w.userOut}").with(user(w.orgAdmin))), "$.data[*].subjectId")
        assertEquals(listOf(w.userIn), names)

        val outName = userRepository.findById(w.userOut).orElseThrow().name
        assertTrue(w.userOut in ids(mockMvc.perform(get("/api/v1/users?q=$outName").with(user(admin))), "$.data.items[*].subjectId"))
        assertTrue(ids(mockMvc.perform(get("/api/v1/organizations").with(user(admin))), "$.data[*].orgId").containsAll(listOf(w.scopeOrg, w.otherOrg)))
    }

    @Test
    fun `조직 단위 관리자는 역할·할당·정책·리소스 API 를 쓸 수 없다`() {
        val w = World()
        val role = roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError()

        mockMvc.perform(get("/api/v1/roles").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/policies").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/resources").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/subjects/${w.userIn}/assignments").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        json(post("/api/v1/assignments"), w.orgAdmin, """{"subjectId":${w.userIn},"roleId":$role}""").andExpect(status().isForbidden)
        json(post("/api/v1/organizations"), w.orgAdmin, """{"orgCode":"X-${System.nanoTime()}","orgName":"새 조직","orgType":"TEAM","parentOrgId":${w.scopeOrg}}""")
            .andExpect(status().isForbidden)
    }

    @Test
    fun `조직 단위 관리자는 범위 안 조직으로만 사용자를 만든다`() {
        val w = World()
        fun body(orgId: Long?) = """{"empNo":"E-${System.nanoTime()}","name":"새 직원"${orgId?.let { ""","primaryOrgId":$it""" }.orEmpty()}}"""

        json(post("/api/v1/users"), w.orgAdmin, body(null)).andExpect(status().isForbidden)
        json(post("/api/v1/users"), w.orgAdmin, body(w.otherOrg)).andExpect(status().isForbidden)
        val created = ids(json(post("/api/v1/users"), w.orgAdmin, body(w.childOrg)).andExpect(status().isCreated), "$.data.subjectId").single()

        assertEquals(w.childOrg, membershipRepository.findActivePrimary(created)?.orgId)
        mockMvc.perform(get("/api/v1/users/$created").with(user(w.orgAdmin))).andExpect(status().isOk)
    }

    @Test
    fun `조직 단위 관리자는 범위 밖 조직으로 옮기거나 소속을 더할 수 없다`() {
        val w = World()

        json(post("/api/v1/subjects/${w.userIn}/primary-membership"), w.orgAdmin, """{"newOrgId":${w.otherOrg}}""").andExpect(status().isForbidden)
        json(post("/api/v1/subjects/${w.userOut}/primary-membership"), w.orgAdmin, """{"newOrgId":${w.childOrg}}""").andExpect(status().isForbidden)
        json(post("/api/v1/memberships"), w.orgAdmin, """{"subjectId":${w.userIn},"orgId":${w.otherOrg},"membershipType":"SECONDARY"}""")
            .andExpect(status().isForbidden)
        json(post("/api/v1/organizations/${w.childOrg}/move"), w.orgAdmin, """{"newParentOrgId":${w.otherOrg}}""").andExpect(status().isForbidden)
        assertEquals(w.scopeOrg, membershipRepository.findActivePrimary(w.userIn)?.orgId)

        json(post("/api/v1/subjects/${w.userIn}/primary-membership"), w.orgAdmin, """{"newOrgId":${w.childOrg}}""").andExpect(status().isOk)
        assertEquals(w.childOrg, membershipRepository.findActivePrimary(w.userIn)?.orgId)
    }

    @Test
    fun `조직 단위 관리자는 같은 조직의 다른 관리자를 바꿀 수 없다 (조회는 된다)`() {
        val w = World()
        val admin = globalAdmin().also { fixture.join(it, w.scopeOrg) }
        val peer = orgAdmin(w.scopeOrg)

        listOf(admin, peer).forEach { target ->
            mockMvc.perform(get("/api/v1/users/$target").with(user(w.orgAdmin))).andExpect(status().isOk)
            mockMvc.perform(post("/api/v1/users/$target/deactivate").with(user(w.orgAdmin))).andExpect(status().isForbidden)
            json(post("/api/v1/users/$target/password"), w.orgAdmin, """{"password":"Another-Pass-123"}""").andExpect(status().isForbidden)
        }
        // 전체 관리자는 조직 단위 관리자를 바꿀 수 있다
        mockMvc.perform(post("/api/v1/users/$peer/deactivate").with(user(admin))).andExpect(status().isOk)
    }

    @Test
    fun `조직 단위 관리자는 곧 관리 역할을 받을 사람도 바꿀 수 없다`() {
        val w = World()
        val auditor = roleRepository.findByRoleCode(IamBootstrap.AUDITOR_ROLE)?.requireId() ?: throw AssertionError()
        // 승인된 JIT 처럼 한 시간 뒤에 시작하는 관리 역할
        val start = Instant.now().plus(1, ChronoUnit.HOURS)
        assignmentService.grantForSource(
            w.userIn, auditor, fixture.globalScopeId(), AssignmentSourceType.JIT, 1L, start, start.plus(4, ChronoUnit.HOURS), null, "점검",
        )

        json(post("/api/v1/users/${w.userIn}/password"), w.orgAdmin, """{"password":"Another-Pass-123"}""").andExpect(status().isForbidden)
        mockMvc.perform(post("/api/v1/users/${w.userIn}/deactivate").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        // 관리 역할과 무관한 사람은 그대로 바꿀 수 있다
        mockMvc.perform(post("/api/v1/users/${w.userChild}/deactivate").with(user(w.orgAdmin))).andExpect(status().isOk)
    }

    @Test
    fun `내 관리 범위는 전체 관리자와 조직 단위 관리자를 구분한다`() {
        val w = World()
        val admin = globalAdmin()

        val scoped = body(mockMvc.perform(get("/api/v1/me/admin-scope").with(user(w.orgAdmin))).andExpect(status().isOk))
        assertEquals(false, JsonPath.read<Boolean>(scoped, "$.data.global"))
        assertEquals(listOf(w.scopeOrg, w.childOrg).sorted(), JsonPath.read<List<Number>>(scoped, "$.data.orgIds").map { it.toLong() })
        val scopedResources = JsonPath.read<List<String>>(scoped, "$.data.resources[*].resource")
        assertEquals(setOf("iam.identity.user", "iam.identity.membership", "iam.identity.organization", "iam.authn.session"), scopedResources.toSet())
        assertEquals(listOf("READ", "CREATE", "UPDATE"), JsonPath.read<List<String>>(scoped, "$.data.resources[?(@.resource == 'iam.identity.user')].actions[*]"))

        val global = body(mockMvc.perform(get("/api/v1/me/admin-scope").with(user(admin))).andExpect(status().isOk))
        assertEquals(true, JsonPath.read<Boolean>(global, "$.data.global"))
        assertEquals(emptyList(), JsonPath.read<List<Number>>(global, "$.data.orgIds"))
        assertTrue("iam.authz.role" in JsonPath.read<List<String>>(global, "$.data.resources[*].resource"))

        val nobody = body(mockMvc.perform(get("/api/v1/me/admin-scope").with(user(fixture.user()))).andExpect(status().isOk))
        assertEquals(false, JsonPath.read<Boolean>(nobody, "$.data.global"))
        assertEquals(emptyList(), JsonPath.read<List<Any>>(nobody, "$.data.resources"))
    }

    @Test
    fun `외부 사용자는 사번 없이 이메일과 고객사 조직으로 만들고, 구분이 응답·검색·토큰에 나온다`() {
        val admin = globalAdmin()
        val customer = fixture.org(OrgType.COMPANY)
        val email = "partner-${System.nanoTime()}@customer.example.com"

        val created = ids(
            json(post("/api/v1/users"), admin, """{"userKind":"EXTERNAL","name":"고객사 담당자","email":"$email","primaryOrgId":$customer}""")
                .andExpect(status().isCreated)
                .andExpect(jsonPath("$.data.userKind").value("EXTERNAL"))
                .andExpect(jsonPath("$.data.empNo").doesNotExist()),
            "$.data.subjectId",
        ).single()
        assertEquals(customer, membershipRepository.findActivePrimary(created)?.orgId)

        json(post("/api/v1/users"), admin, """{"userKind":"EXTERNAL","name":"중복","email":"$email","primaryOrgId":$customer}""")
            .andExpect(status().isConflict)
        json(post("/api/v1/users"), admin, """{"userKind":"EXTERNAL","name":"이메일 없음","primaryOrgId":$customer}""").andExpect(status().isConflict)
        json(post("/api/v1/users"), admin, """{"userKind":"EXTERNAL","name":"조직 없음","email":"x-$email"}""").andExpect(status().isConflict)
        json(post("/api/v1/users"), admin, """{"name":"사번 없는 임직원"}""").andExpect(status().isConflict)

        assertEquals(listOf(created), ids(mockMvc.perform(get("/api/v1/users?q=$email&kind=EXTERNAL").with(user(admin))), "$.data.items[*].subjectId"))
        assertEquals(emptyList(), ids(mockMvc.perform(get("/api/v1/users?q=$email&kind=EMPLOYEE").with(user(admin))), "$.data.items[*].subjectId"))

        val claims = claimsProvider.claimsOf(created)
        assertEquals("EXTERNAL", claims["user_kind"])
        assertNull(claims["emp_no"])
        assertEquals("EMPLOYEE", claimsProvider.claimsOf(admin)["user_kind"])
        assertFalse(userRepository.findById(created).orElseThrow().empNo != null)
        assertEquals(UserKind.EXTERNAL, userRepository.findById(created).orElseThrow().userKind)
    }

    @Test
    fun `관리 콘솔 권한이 있는 역할은 조직 역할 규칙으로 줄 수 없고, 규칙에 쓰는 역할에 콘솔 권한을 더할 수도 없다`() {
        val admin = globalAdmin()
        val team = fixture.org(OrgType.TEAM)
        for (code in listOf(IamBootstrap.ADMIN_ROLE, IamBootstrap.ORG_ADMIN_ROLE)) {
            val roleId = roleRepository.findByRoleCode(code)?.requireId() ?: throw AssertionError(code)
            json(post("/api/v1/organization-roles"), admin, """{"orgId":$team,"roleId":$roleId}""").andExpect(status().isConflict)
        }

        val plain = fixture.role().requireId()
        json(post("/api/v1/organization-roles"), admin, """{"orgId":$team,"roleId":$plain}""").andExpect(status().isCreated)
        val consolePermission = permissionRepository
            .findByResourceIdAndActionAndIsActiveTrue(authorizer.resourceId(ApiResources.USER), PermissionAction.READ).first().requireId()
        json(post("/api/v1/roles/$plain/permissions"), admin, """{"permissionId":$consolePermission}""").andExpect(status().isConflict)
    }

    @Test
    fun `예전에 만든 콘솔 역할 조직 규칙이 있어도 소속을 바꿔 관리 역할을 얻을 수 없다`() {
        val w = World()
        val auditor = roleRepository.findByRoleCode(IamBootstrap.AUDITOR_ROLE)?.requireId() ?: throw AssertionError()
        // API 로는 만들 수 없는 규칙이라 저장소에 직접 넣는다 (규칙 생성을 막기 전에 만든 데이터)
        organizationRoleRepository.save(OrganizationRole(w.childOrg, auditor, fixture.globalScopeId(), false, Instant.now()))

        json(post("/api/v1/memberships"), w.orgAdmin, """{"subjectId":${w.userIn},"orgId":${w.childOrg},"membershipType":"SECONDARY"}""")
            .andExpect(status().isConflict)
        assertTrue(assignmentService.effectiveAssignments(w.userIn).none { it.roleId == auditor })
    }

    private fun orgAdmin(orgId: Long): Long = fixture.user("조직 관리자").also {
        fixture.join(it, orgId)
        val scope = catalogService.createScope("ORG-ADMIN-${System.nanoTime()}", "조직 범위", ScopeType.ORGANIZATION, orgId = orgId, includeDescendants = true)
        val role = roleRepository.findByRoleCode(IamBootstrap.ORG_ADMIN_ROLE)?.requireId() ?: throw AssertionError("IAM_ORG_ADMIN 역할 없음")
        assignmentService.assignDirect(it, role, scope.requireId())
    }

    private fun globalAdmin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun member(orgId: Long): Long = fixture.user("구성원-${System.nanoTime()}").also { fixture.join(it, orgId) }

    private fun json(builder: MockHttpServletRequestBuilder, subjectId: Long, body: String) =
        mockMvc.perform(builder.with(user(subjectId)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun body(result: ResultActions): String = result.andReturn().response.contentAsString

    private fun ids(result: ResultActions, path: String): List<Long> {
        val value = JsonPath.read<Any>(body(result), path)
        return if (value is List<*>) value.map { (it as Number).toLong() } else listOf((value as Number).toLong())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
