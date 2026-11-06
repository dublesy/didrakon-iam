package com.didrakon.iam.governance

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.governance.breakglass.BreakGlassPolicy
import com.didrakon.iam.governance.breakglass.BreakGlassPolicyRepository
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.breakglass.BreakGlassSessionRepository
import com.didrakon.iam.governance.breakglass.BreakGlassStatus
import com.didrakon.iam.governance.delegation.DelegationRepository
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.delegation.DelegationStatus
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserRepository
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 비상 접근·위임·접근 요청 운영 API 와 본인 조회 API. 테스트마다 롤백된다 */
@AuthzTest
class GovernanceOpsApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val breakGlassPolicyRepository: BreakGlassPolicyRepository,
    private val breakGlassSessionRepository: BreakGlassSessionRepository,
    private val breakGlassService: BreakGlassService,
    private val delegationService: DelegationService,
    private val delegationRepository: DelegationRepository,
    private val accessRequestService: AccessRequestService,
    private val userRepository: UserRepository,
    private val userService: UserService,
    private val groupRepository: UserGroupRepository,
    private val groupMemberService: GroupMemberService,
    private val jdbc: JdbcTemplate,
    private val permissionRepository: PermissionRepository,
    private val catalogService: AuthzCatalogService,
    private val authorizer: AdminAuthorizer,
) {
    private val now: Instant get() = Instant.now()

    // ---------- 비상 접근 정책 ----------

    @Test
    fun `비상 접근 정책을 목록에서 보고 고치며, 끈 정책은 본인 목록에서 빠지고 시작할 수 없다`() {
        val admin = admin()
        val role = fixture.role()
        val policyId = breakGlassPolicyRepository.save(
            BreakGlassPolicy("장애 대응", role.requireId(), fixture.globalScopeId(), maxDurationMinutes = 60, requireMfa = false),
        ).requireId()
        val user = fixture.user("당직자")

        mockMvc.perform(get("/api/v1/break-glass-policies").with(token(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].roleName").value(role.roleName))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].isActive").value(true))

        json(put("/api/v1/break-glass-policies/$policyId"), admin, """{"policyName":"결제 장애","maxDurationMinutes":30,"requireReason":true,"requireApproval":false,"requireMfa":true}""")
            .andExpect(status().isOk)
        json(put("/api/v1/break-glass-policies/$policyId"), admin, """{"policyName":"x","maxDurationMinutes":0}""").andExpect(status().isConflict)
        val policy = breakGlassPolicyRepository.findById(policyId).orElseThrow()
        assertEquals("결제 장애", policy.policyName)
        assertEquals(30, policy.maxDurationMinutes)
        assertTrue(policy.requireMfa)

        mockMvc.perform(post("/api/v1/break-glass-policies/$policyId/deactivate").with(token(admin))).andExpect(status().isOk)

        mockMvc.perform(get("/api/v1/me/break-glass-policies").with(token(user)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)]").isEmpty)
        json(post("/api/v1/me/break-glass"), user, """{"policyId":$policyId,"reason":"장애"}""").andExpect(status().isNotFound)

        mockMvc.perform(post("/api/v1/break-glass-policies/$policyId/activate").with(token(admin))).andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/me/break-glass-policies").with(token(user)))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].policyName").value("결제 장애"))
        json(post("/api/v1/me/break-glass"), user, """{"policyId":$policyId,"reason":"장애"}""")
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.sessionId").isNumber)

        assertEquals(listOf("UPDATE", "DEACTIVATE", "ACTIVATE"), auditActions("BREAK_GLASS_POLICY", policyId))
    }

    @Test
    fun `승인 없이 시작하는 비상 접근 정책의 역할에는 관리 콘솔 권한을 더할 수 없고, 그런 역할의 정책은 다시 켤 수 없다`() {
        val admin = admin()
        val roleId = fixture.role().requireId()
        val policyId = breakGlassPolicyRepository.save(
            BreakGlassPolicy("장애 대응", roleId, fixture.globalScopeId(), maxDurationMinutes = 60, requireApproval = false, requireMfa = false),
        ).requireId()
        val consolePermission = permissionRepository
            .findByResourceIdAndActionAndIsActiveTrue(authorizer.resourceId(ApiResources.USER), PermissionAction.READ).first().requireId()

        json(post("/api/v1/roles/$roleId/permissions"), admin, """{"permissionId":$consolePermission}""").andExpect(status().isConflict)

        // 꺼 둔 사이 역할에 콘솔 권한이 생기면(예전 데이터) 다시 켤 수 없다
        mockMvc.perform(post("/api/v1/break-glass-policies/$policyId/deactivate").with(token(admin))).andExpect(status().isOk)
        catalogService.grantPermission(roleId, consolePermission)
        mockMvc.perform(post("/api/v1/break-glass-policies/$policyId/activate").with(token(admin))).andExpect(status().isConflict)
        assertFalse(breakGlassPolicyRepository.findById(policyId).orElseThrow().isActive)
    }

    @Test
    fun `승인 대기 중에 정책을 끄면 그 비상 접근 요청은 승인할 수 없다`() {
        val roleId = fixture.role().requireId()
        val policyId = breakGlassPolicyRepository.save(
            BreakGlassPolicy("승인 필요", roleId, fixture.globalScopeId(), maxDurationMinutes = 60, requireApproval = true, requireMfa = false),
        ).requireId()
        val user = fixture.user()
        val request = breakGlassService.activate(user, policyId, "복구", mfaVerified = false).pendingRequest ?: throw AssertionError()
        val admin = admin()
        mockMvc.perform(post("/api/v1/break-glass-policies/$policyId/deactivate").with(token(admin))).andExpect(status().isOk)

        json(post("/api/v1/access-requests/${request.requireId()}/approve"), admin, "{}").andExpect(status().isConflict)
        assertTrue(assignmentRepository.findEffective(user, now).none { it.roleId == roleId })
    }

    @Test
    fun `비상 접근 정책에 대상 그룹을 지정하면 그 구성원에게만 본인 목록에 보이고 시작되며, 비우면 누구나 쓴다`() {
        val admin = admin()
        val roleId = fixture.role().requireId()
        val global = fixture.globalScopeId()
        val group = groupRepository.save(UserGroup("ONCALL-${System.nanoTime()}", "당직자 그룹", GroupType.STATIC)).requireId()
        val member = fixture.user("당직자").also { groupMemberService.addMember(group, it) }
        val outsider = fixture.user("일반 사용자")

        // 비상 접근 관리자는 그룹 관리 권한이 없어도 대상 그룹 선택지를 본다
        mockMvc.perform(get("/api/v1/break-glass-policies/group-options").with(token(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.groupId == $group)].groupName").value("당직자 그룹"))
        mockMvc.perform(get("/api/v1/break-glass-policies/group-options").with(token(outsider))).andExpect(status().isForbidden)

        val created = json(
            post("/api/v1/break-glass-policies"), admin,
            """{"policyName":"당직 비상","roleId":$roleId,"scopeId":$global,"maxDurationMinutes":30,"requireReason":true,"requireApproval":false,"requireMfa":true,"eligibleGroupId":$group}""",
        ).andExpect(status().isCreated).andReturn().response.contentAsString
        val policyId = Regex("\"id\":(\\d+)").find(created)?.groupValues?.get(1) ?: throw AssertionError(created)

        mockMvc.perform(get("/api/v1/break-glass-policies").with(token(admin)))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].eligibleGroupId").value(group.toInt()))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].eligibleGroupName").value("당직자 그룹"))
        mockMvc.perform(get("/api/v1/me/break-glass-policies").with(token(outsider)))
            .andExpect(status().isOk).andExpect(jsonPath("$.data[?(@.policyId == $policyId)]").isEmpty)
        mockMvc.perform(get("/api/v1/me/break-glass-policies").with(token(member)))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].policyName").value("당직 비상"))

        json(post("/api/v1/me/break-glass"), outsider, """{"policyId":$policyId,"reason":"장애"}""")
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error.message").value("이 비상 접근 정책을 쓸 수 있는 그룹의 구성원이 아닙니다"))
        assertTrue(assignmentRepository.findEffective(outsider, now).none { it.roleId == roleId })
        json(post("/api/v1/me/break-glass"), member, """{"policyId":$policyId,"reason":"장애"}""")
            .andExpect(status().isOk).andExpect(jsonPath("$.data.sessionId").isNumber)

        // 대상 그룹을 비우면 누구나
        json(put("/api/v1/break-glass-policies/$policyId"), admin, """{"policyName":"당직 비상","maxDurationMinutes":30,"requireReason":true,"requireApproval":false,"requireMfa":true}""")
            .andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/me/break-glass-policies").with(token(outsider)))
            .andExpect(jsonPath("$.data[?(@.policyId == $policyId)].policyName").value("당직 비상"))
        json(post("/api/v1/me/break-glass"), outsider, """{"policyId":$policyId,"reason":"장애"}""")
            .andExpect(status().isOk).andExpect(jsonPath("$.data.sessionId").isNumber)
        assertTrue(jdbc.queryForList("SELECT after_value FROM audit_event WHERE resource_type = 'BREAK_GLASS_POLICY' AND resource_id = ?", policyId)
            .any { it["after_value"].toString().contains("eligibleGroupId") })
    }

    // ---------- 비상 접근 세션 ----------

    @Test
    fun `관리자가 비상 접근 세션을 끝내면 받은 역할이 회수되고 본인 목록에는 본인 세션만 보인다`() {
        val roleId = fixture.role().requireId()
        val policyId = breakGlassPolicyRepository.save(
            BreakGlassPolicy("비상", roleId, fixture.globalScopeId(), maxDurationMinutes = 60, requireMfa = true),
        ).requireId()
        val user = fixture.user("당직자")
        val other = fixture.user("다른 사람")

        json(post("/api/v1/me/break-glass"), user, """{"policyId":$policyId,"reason":"결제 장애"}""", amr = listOf("pwd"))
            .andExpect(status().isConflict)
            .andExpect(jsonPath("$.error.message").value("비상 접근은 MFA 를 거친 로그인에서만 시작할 수 있습니다"))
        val session = breakGlassService.activate(user, policyId, "결제 장애", mfaVerified = true).session ?: throw AssertionError()
        val sessionId = session.requireId()
        val admin = admin()

        mockMvc.perform(get("/api/v1/break-glass-sessions").with(token(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.sessionId == $sessionId)].subjectName").value("당직자"))
            .andExpect(jsonPath("$.data[?(@.sessionId == $sessionId)].policyName").value("비상"))
            .andExpect(jsonPath("$.data[?(@.sessionId == $sessionId)].status").value("ACTIVE"))

        mockMvc.perform(post("/api/v1/break-glass-sessions/$sessionId/end").with(token(admin))).andExpect(status().isOk)
        mockMvc.perform(post("/api/v1/break-glass-sessions/$sessionId/end").with(token(admin))).andExpect(status().isConflict)

        val ended = breakGlassSessionRepository.findById(sessionId).orElseThrow()
        assertEquals(BreakGlassStatus.REVOKED, ended.status)
        assertEquals(admin, ended.revokedBy)
        val assignment = assignmentRepository.findById(ended.assignmentId ?: throw AssertionError()).orElseThrow()
        assertEquals(AssignmentStatus.REVOKED, assignment.status)
        assertTrue(assignmentRepository.findEffective(user, now).none { it.roleId == roleId })

        mockMvc.perform(get("/api/v1/me/break-glass-sessions").with(token(user)))
            .andExpect(jsonPath("$.data[?(@.sessionId == $sessionId)].status").value("REVOKED"))
            .andExpect(jsonPath("$.data[?(@.sessionId == $sessionId)].revokedByName").value("관리자"))
        mockMvc.perform(get("/api/v1/me/break-glass-sessions").with(token(other)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data").isEmpty)
    }

    // ---------- 위임 ----------

    @Test
    fun `관리자가 위임을 회수하면 대리인의 할당이 사라지고, 본인 위임 목록은 한 것과 받은 것으로 나뉜다`() {
        val role = fixture.role()
        val roleId = role.requireId()
        val delegator = fixture.user("위임자")
        val delegate = fixture.user("대리인")
        assignmentService.assignDirect(delegator, roleId)

        mockMvc.perform(get("/api/v1/me/access-options").with(token(delegator)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.delegatable[?(@.roleId == $roleId)].scopeCode").value("GLOBAL"))
            .andExpect(jsonPath("$.data.roles[?(@.roleId == $roleId)].roleName").value(role.roleName))
        mockMvc.perform(get("/api/v1/me/access-options").with(token(delegate)))
            .andExpect(jsonPath("$.data.delegatable[?(@.roleId == $roleId)]").isEmpty)

        val delegation = delegationService.delegate(delegator, delegate, roleId, fixture.globalScopeId(), now, now.plusSeconds(3600), "휴가")
        val delegationId = delegation.requireId()

        mockMvc.perform(get("/api/v1/me/delegations").with(token(delegator)))
            .andExpect(jsonPath("$.data.given[?(@.delegationId == $delegationId)].delegateName").value("대리인"))
            .andExpect(jsonPath("$.data.received").isEmpty)
        mockMvc.perform(get("/api/v1/me/delegations").with(token(delegate)))
            .andExpect(jsonPath("$.data.given").isEmpty)
            .andExpect(jsonPath("$.data.received[?(@.delegationId == $delegationId)].delegatorName").value("위임자"))

        val admin = admin()
        mockMvc.perform(get("/api/v1/delegations").with(token(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.delegationId == $delegationId)].status").value("ACTIVE"))
            .andExpect(jsonPath("$.data[?(@.delegationId == $delegationId)].roleName").value(role.roleName))

        json(post("/api/v1/delegations/$delegationId/revoke"), admin, """{"reason":"퇴사 예정"}""").andExpect(status().isOk)

        assertEquals(DelegationStatus.REVOKED, delegationRepository.findById(delegationId).orElseThrow().status)
        assertTrue(assignmentRepository.findEffective(delegate, now).none { it.roleId == roleId && it.sourceType == AssignmentSourceType.DELEGATION })
        assertTrue(assignmentRepository.findEffective(delegator, now).any { it.roleId == roleId })
        json(post("/api/v1/delegations/$delegationId/revoke"), admin, "{}").andExpect(status().isConflict)
    }

    @Test
    fun `위임 대상은 사번이 같은 사용 중인 사용자만 찾는다`() {
        val caller = fixture.user()
        val target = fixture.user("동료")
        val empNo = userRepository.findById(target).orElseThrow().empNo ?: throw AssertionError()

        mockMvc.perform(get("/api/v1/me/people").param("empNo", empNo).with(token(caller)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.subjectId").value(target))
            .andExpect(jsonPath("$.data.name").value("동료"))
        mockMvc.perform(get("/api/v1/me/people").param("empNo", empNo.dropLast(1)).with(token(caller))).andExpect(status().isNotFound)

        userService.changeStatus(target, SubjectStatus.DISABLED)
        mockMvc.perform(get("/api/v1/me/people").param("empNo", empNo).with(token(caller))).andExpect(status().isNotFound)
    }

    // ---------- 접근 요청 ----------

    @Test
    fun `처리 기록에는 끝난 요청과 승인자 결정이 있고 대기 요청은 없으며, 본인 요청 목록은 본인 것만 준다`() {
        val requester = fixture.user("요청자")
        val other = fixture.user("다른 요청자")
        val approver = fixture.user("승인자")
        val (approvedRole, rejectedRole, pendingRole) = Triple(fixture.role().requireId(), fixture.role().requireId(), fixture.role().requireId())
        val start = now
        val end = now.plusSeconds(3600)

        json(post("/api/v1/me/access-requests"), requester, """{"roleId":$approvedRole,"reason":"점검","requestedStart":"$start","requestedEnd":"$end"}""")
            .andExpect(status().isCreated)
        val approved = accessRequestService.requestsOf(requester).single()
        accessRequestService.approve(approved.requireId(), approver, "확인")
        val rejected = accessRequestService.requestJit(requester, rejectedRole, "점검", start, end)
        accessRequestService.reject(rejected.requireId(), approver, "사유 부족")
        val pending = accessRequestService.requestJit(requester, pendingRole, "점검", start, end)
        val othersRequest = accessRequestService.requestJit(other, pendingRole, "남의 요청", start, end)

        val admin = admin()
        mockMvc.perform(get("/api/v1/access-requests/history").with(token(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.requestId == ${approved.requireId()})].status").value("APPROVED"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${approved.requireId()})].subjectName").value("요청자"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${approved.requireId()})].decisions[0].approverName").value("승인자"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${approved.requireId()})].decisions[0].comment").value("확인"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${rejected.requireId()})].status").value("REJECTED"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${rejected.requireId()})].decisions[0].status").value("REJECTED"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${approved.requireId()} && @.closedAt != null)]").isNotEmpty)
            .andExpect(jsonPath("$.data[?(@.requestId == ${rejected.requireId()} && @.closedAt != null)]").isNotEmpty)
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()})]").isEmpty)

        mockMvc.perform(get("/api/v1/me/access-requests").with(token(requester)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.length()").value(3))
            .andExpect(jsonPath("$.data[?(@.requestId == ${othersRequest.requireId()})]").isEmpty)
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()})].status").value("PENDING"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()} && @.closedAt == null)]").isNotEmpty)

        mockMvc.perform(post("/api/v1/me/access-requests/${othersRequest.requireId()}/cancel").with(token(requester))).andExpect(status().isConflict)
        mockMvc.perform(post("/api/v1/me/access-requests/${pending.requireId()}/cancel").with(token(requester))).andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/access-requests/history").with(token(admin)))
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()})].status").value("CANCELLED"))
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()} && @.closedAt != null)]").isNotEmpty)
        mockMvc.perform(get("/api/v1/me/access-requests").with(token(requester)))
            .andExpect(jsonPath("$.data[?(@.requestId == ${pending.requireId()} && @.closedAt != null)]").isNotEmpty)
    }

    // ---------- 권한 ----------

    @Test
    fun `운영 목록은 관리 권한이 있어야 하고 본인 조회는 사용 중인 사람만 쓴다`() {
        val user = fixture.user()
        listOf("/api/v1/break-glass-policies", "/api/v1/break-glass-sessions", "/api/v1/delegations", "/api/v1/access-requests/history").forEach {
            mockMvc.perform(get(it).with(token(user))).andExpect(status().isForbidden)
        }
        mockMvc.perform(post("/api/v1/delegations/1/revoke").with(token(user)).contentType(MediaType.APPLICATION_JSON).content("{}"))
            .andExpect(status().isForbidden)

        val selfPaths = listOf(
            "/api/v1/me/access-requests", "/api/v1/me/delegations", "/api/v1/me/break-glass-policies",
            "/api/v1/me/break-glass-sessions", "/api/v1/me/access-options",
        )
        selfPaths.forEach { mockMvc.perform(get(it).with(token(user))).andExpect(status().isOk) }
        userService.changeStatus(user, SubjectStatus.DISABLED)
        selfPaths.forEach { mockMvc.perform(get(it).with(token(user))).andExpect(status().isForbidden) }
    }

    @Test
    fun `관리 콘솔 권한이 있는 역할의 비상 접근 정책은 승인을 꺼서 만들거나 바꿀 수 없다`() {
        val admin = admin()
        val adminRole = roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError()
        val global = fixture.globalScopeId()
        fun create(requireApproval: Boolean) = json(
            post("/api/v1/break-glass-policies"), admin,
            """{"policyName":"관리자 비상","roleId":$adminRole,"scopeId":$global,"maxDurationMinutes":30,"requireReason":true,"requireApproval":$requireApproval,"requireMfa":true}""",
        )
        create(false).andExpect(status().isConflict)
        val body = create(true).andExpect(status().isCreated).andReturn().response.contentAsString
        val policyId = Regex("\"id\":(\\d+)").find(body)?.groupValues?.get(1) ?: throw AssertionError(body)
        json(put("/api/v1/break-glass-policies/$policyId"), admin, """{"policyName":"관리자 비상","maxDurationMinutes":30,"requireReason":true,"requireApproval":false,"requireMfa":true}""")
            .andExpect(status().isConflict)
    }

    private fun json(builder: MockHttpServletRequestBuilder, subjectId: Long, body: String, amr: List<String> = listOf("pwd", "otp")) =
        mockMvc.perform(builder.with(token(subjectId, amr)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun auditActions(resourceType: String, id: Long): List<String> = jdbc.queryForList(
        "SELECT action FROM audit_event WHERE resource_type = ? AND resource_id = ? ORDER BY event_id",
        String::class.java, resourceType, id.toString(),
    ).filterNotNull()

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun token(subjectId: Long, amr: List<String> = listOf("pwd", "otp")) =
        jwt().jwt { it.subject(subjectId.toString()).claim("amr", amr) }
}
