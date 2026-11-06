package com.didrakon.iam.api

import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserRepository
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 관리 화면의 수정·사용 안 함·회수. 테스트마다 롤백된다 */
@AuthzTest
class AdminEditApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val assignmentService: RoleAssignmentService,
    private val userRepository: UserRepository,
    private val groupService: GroupService,
    private val groupMemberService: GroupMemberService,
    private val clientService: SsoClientService,
    private val ssoClientRepository: SsoClientRepository,
    private val registeredClientRepository: RegisteredClientRepository,
    private val pdp: PolicyDecisionPoint,
    private val jdbc: JdbcTemplate,
    private val userService: com.didrakon.iam.identity.subject.UserService,
    private val entityManager: jakarta.persistence.EntityManager,
) {
    @Test
    fun `사용자 정보를 고치고 사용 안 함으로 바꾸면 감사 기록에 전후 값이 남는다`() {
        val admin = admin()
        val userId = fixture.user("변경 전")

        json(put("/api/v1/users/$userId"), admin, """{"name":"변경 후","email":"after@example.com","phone":"010-0000-0000"}""")
            .andExpect(status().isOk)
        mockMvc.perform(post("/api/v1/users/$userId/deactivate").with(user(admin))).andExpect(status().isOk)

        val user = userRepository.findById(userId).orElseThrow()
        assertEquals("변경 후", user.name)
        assertEquals("변경 후", user.subjectName)
        assertEquals(SubjectStatus.DISABLED, user.status)
        assertEquals(listOf("UPDATE", "DEACTIVATE"), auditActions("USER", userId))
    }

    @Test
    fun `퇴사 처리하면 소속·그룹·역할이 모두 정리되고 다시 사용할 수 없다`() {
        val admin = admin()
        val org = fixture.org(OrgType.TEAM)
        val userId = fixture.user().also { fixture.join(it, org) }
        val group = groupService.create("G-${System.nanoTime()}", "그룹", GroupType.STATIC, null).requireId()
        groupMemberService.addMember(group, userId)
        assignmentService.assignDirect(userId, fixture.role().requireId())

        json(post("/api/v1/users/$userId/retire"), admin, """{"retireDate":"2026-10-31"}""").andExpect(status().isOk)

        val user = userRepository.findById(userId).orElseThrow()
        assertEquals(SubjectStatus.RETIRED, user.status)
        assertEquals(java.time.LocalDate.of(2026, 10, 31), user.retireDate)
        assertEquals(emptyList(), assignmentService.effectiveAssignments(userId))
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM group_member WHERE subject_id = ?", Int::class.java, userId))
        assertEquals(
            0,
            jdbc.queryForObject("SELECT COUNT(*) FROM subject_organization WHERE subject_id = ? AND (valid_until IS NULL OR valid_until > NOW())", Int::class.java, userId),
        )
        mockMvc.perform(post("/api/v1/users/$userId/activate").with(user(admin))).andExpect(status().is4xxClientError)
    }

    @Test
    fun `퇴사일이 미래면 예약만 하고 취소할 수 있으며, 예정일이 되면 스케줄러가 처리한다`() {
        val admin = admin()
        val userId = fixture.user()
        val future = java.time.LocalDate.now().plusDays(30)

        json(post("/api/v1/users/$userId/retire"), admin, """{"retireDate":"$future"}""").andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/users/$userId").with(user(admin)))
            .andExpect(jsonPath("$.data.status").value("ACTIVE"))
            .andExpect(jsonPath("$.data.retireDate").value(future.toString()))

        mockMvc.perform(delete("/api/v1/users/$userId/retire").with(user(admin))).andExpect(status().isOk)
        assertNull(userRepository.findById(userId).orElseThrow().retireDate)

        json(post("/api/v1/users/$userId/retire"), admin, """{"retireDate":"$future"}""").andExpect(status().isOk)
        assertEquals(0, userService.retireDue(), "예정일 전에는 처리하지 않는다")
        jdbc.update("UPDATE `user` SET retire_date = CURDATE() - INTERVAL 1 DAY WHERE subject_id = ?", userId)
        userRepository.flush()
        entityManager.clear()

        assertTrue(userService.retireDue() >= 1)
        assertEquals(SubjectStatus.RETIRED, userRepository.findById(userId).orElseThrow().status)
        assertEquals(listOf("SCHEDULE_RETIRE", "CANCEL_RETIRE", "SCHEDULE_RETIRE", "RETIRE"), auditActions("USER", userId))
    }

    @Test
    fun `구성원이 있는 조직·그룹은 끌 수 없고, 비우면 끌 수 있다`() {
        val admin = admin()
        val org = fixture.org(OrgType.TEAM)
        val member = fixture.user().also { fixture.join(it, org) }
        val group = groupService.create("G-${System.nanoTime()}", "그룹", GroupType.STATIC, null).requireId()
        groupMemberService.addMember(group, member)

        mockMvc.perform(post("/api/v1/organizations/$org/deactivate").with(user(admin))).andExpect(status().is4xxClientError)
        mockMvc.perform(post("/api/v1/groups/$group/deactivate").with(user(admin))).andExpect(status().is4xxClientError)

        val emptyOrg = fixture.org(OrgType.TEAM)
        mockMvc.perform(post("/api/v1/organizations/$emptyOrg/deactivate").with(user(admin))).andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/organizations").with(user(admin)))
            .andExpect(jsonPath("$.data[?(@.orgId == $emptyOrg)].isActive").value(false))
    }

    @Test
    fun `역할에서 권한을 빼면 목록에서 사라지고 판정도 거부한다`() {
        val admin = admin()
        val userId = fixture.user()
        val resource = fixture.resource().requireId()
        val role = fixture.roleAllowing(resource)
        assignmentService.assignDirect(userId, role.requireId())
        assertEquals(Decision.ALLOW, decide(userId, resource))

        val rolePermissionId = rolePermissionRepository.findByRoleId(role.requireId()).single().requireId()
        mockMvc.perform(delete("/api/v1/role-permissions/$rolePermissionId").with(user(admin))).andExpect(status().isOk)

        mockMvc.perform(get("/api/v1/roles/${role.requireId()}").with(user(admin))).andExpect(jsonPath("$.data.permissions.length()").value(0))
        assertEquals(Decision.DENY, decide(userId, resource))
    }

    @Test
    fun `권한·범위를 끄면 판정에서 빠지고 다시 켜면 돌아온다`() {
        val admin = admin()
        val userId = fixture.user()
        val resource = fixture.resource().requireId()
        val role = fixture.roleAllowing(resource)
        assignmentService.assignDirect(userId, role.requireId())
        val permissionId = rolePermissionRepository.findByRoleId(role.requireId()).single().permissionId

        mockMvc.perform(post("/api/v1/permissions/$permissionId/deactivate").with(user(admin))).andExpect(status().isOk)
        assertEquals(Decision.DENY, decide(userId, resource))
        mockMvc.perform(post("/api/v1/permissions/$permissionId/activate").with(user(admin))).andExpect(status().isOk)
        assertEquals(Decision.ALLOW, decide(userId, resource))

        mockMvc.perform(post("/api/v1/scopes/${fixture.globalScopeId()}/deactivate").with(user(admin))).andExpect(status().is4xxClientError)
    }

    @Test
    fun `SSO 클라이언트를 끄면 client_id 로 찾을 수 없고, 관리 콘솔 클라이언트는 끌 수 없다`() {
        val admin = admin()
        val code = "web-${System.nanoTime()}"
        val client = clientService.register(ClientRegistration(code, "웹", ClientType.WEB, redirectUris = setOf("https://app.example.com/cb")))
        assertNotNull(registeredClientRepository.findByClientId(code))

        mockMvc.perform(post("/api/v1/clients/${client.ssoClient.requireId()}/deactivate").with(user(admin))).andExpect(status().isOk)
        assertNull(registeredClientRepository.findByClientId(code))

        val console = ssoClientRepository.findByClientCode("iam-admin")?.requireId() ?: throw AssertionError()
        mockMvc.perform(post("/api/v1/clients/$console/deactivate").with(user(admin))).andExpect(status().is4xxClientError)
    }

    @Test
    fun `관리 콘솔 자신의 리소스·권한은 끌 수 없다`() {
        val admin = admin()
        val consoleClient = ssoClientRepository.findByClientCode("iam-admin")?.requireId() ?: throw AssertionError()
        val consoleResource = jdbc.queryForObject(
            "SELECT resource_id FROM resource WHERE client_id = ? AND resource_key = 'iam.identity.user'", Long::class.java, consoleClient,
        ) ?: throw AssertionError()
        val consolePermission = jdbc.queryForObject("SELECT permission_id FROM permission WHERE resource_id = ? LIMIT 1", Long::class.java, consoleResource)
            ?: throw AssertionError()

        mockMvc.perform(post("/api/v1/resources/$consoleResource/deactivate").with(user(admin))).andExpect(status().is4xxClientError)
        mockMvc.perform(post("/api/v1/permissions/$consolePermission/deactivate").with(user(admin))).andExpect(status().is4xxClientError)
    }

    @Test
    fun `역할 정보를 고치면 코드는 그대로이고 바뀐 값이 조회된다`() {
        val admin = admin()
        val role = fixture.role()

        json(put("/api/v1/roles/${role.requireId()}"), admin, """{"roleName":"새 이름","roleType":"CUSTOM","priority":5,"isSensitive":true,"isPrivileged":false}""")
            .andExpect(status().isOk)

        mockMvc.perform(get("/api/v1/roles/${role.requireId()}").with(user(admin)))
            .andExpect(jsonPath("$.data.role.roleName").value("새 이름"))
            .andExpect(jsonPath("$.data.role.roleCode").value(role.roleCode))
            .andExpect(jsonPath("$.data.role.isSensitive").value(true))
        assertEquals(listOf("UPDATE"), auditActions("ROLE", role.requireId()))
    }

    private fun decide(subjectId: Long, resourceId: Long) = pdp.decide(AuthorizationRequest(subjectId, resourceId, PermissionAction.READ)).decision

    private fun json(builder: org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder, admin: Long, body: String) =
        mockMvc.perform(builder.with(user(admin)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun auditActions(resourceType: String, id: Long): List<String> = jdbc.queryForList(
        "SELECT action FROM audit_event WHERE resource_type = ? AND resource_id = ? ORDER BY event_id",
        String::class.java, resourceType, id.toString(),
    ).filterNotNull()

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
