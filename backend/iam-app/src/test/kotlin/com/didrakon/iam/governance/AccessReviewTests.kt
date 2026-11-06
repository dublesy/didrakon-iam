package com.didrakon.iam.governance

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.governance.delegation.DelegationRepository
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.delegation.DelegationStatus
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.review.AccessReviewDecision
import com.didrakon.iam.governance.review.AccessReviewItem
import com.didrakon.iam.governance.review.AccessReviewService
import com.didrakon.iam.governance.review.AccessReviewSpec
import com.didrakon.iam.governance.review.AccessReviewStatus
import com.didrakon.iam.governance.review.ReviewScopeType
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.nio.charset.StandardCharsets
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 접근 재검토 캠페인: 대상 스냅샷, 검토자, 결정의 효력, 증적. 테스트마다 롤백된다 */
@AuthzTest
class AccessReviewTests @Autowired constructor(
    private val reviewService: AccessReviewService,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val organizationRoleService: OrganizationRoleService,
    private val accessRequestService: AccessRequestService,
    private val delegationService: DelegationService,
    private val delegationRepository: DelegationRepository,
    private val membershipService: MembershipService,
    private val roleRepository: RoleRepository,
    private val pdp: PolicyDecisionPoint,
    private val fixture: AuthzFixture,
    private val mockMvc: MockMvc,
    private val jdbc: JdbcTemplate,
) {
    private val now: Instant get() = Instant.now()

    @Test
    fun `조직 범위 캠페인은 하위 조직 주 소속자의 대상 출처 할당만 담고 검토자는 주 소속 조직의 관리자다`() {
        val company = fixture.org(OrgType.COMPANY)
        val team = fixture.org(OrgType.TEAM, company)
        val other = fixture.org(OrgType.TEAM)
        val manager1 = fixture.user("관리자1").also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val manager2 = fixture.user("관리자2").also { membershipService.join(it, team, MembershipType.SECONDARY, isManager = true) }
        val member = fixture.user("팀원").also { fixture.join(it, team) }
        val companyMember = fixture.user("본사").also { fixture.join(it, company) }
        val outsider = fixture.user("외부").also { fixture.join(it, other) }
        val role = fixture.role().requireId()
        listOf(manager1, member, companyMember, outsider).forEach { assignmentService.assignDirect(it, role) }
        val jit = jit(member, fixture.role().requireId())
        organizationRoleService.create(team, fixture.role().requireId()) // ORGANIZATION 할당은 대상이 아니다

        val campaign = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = company), null)
        val items = reviewService.items(campaign.requireId())

        assertEquals(
            setOf(member to AssignmentSourceType.DIRECT, member to AssignmentSourceType.JIT, companyMember to AssignmentSourceType.DIRECT,
                manager1 to AssignmentSourceType.DIRECT),
            items.map { it.subjectId to it.sourceType }.toSet(),
        )
        assertTrue(items.any { it.assignmentId == jit.requireId() })
        assertEquals(minOf(manager1, manager2), items.first { it.subjectId == member }.reviewerId)
        assertEquals(manager2, items.single { it.subjectId == manager1 }.reviewerId, "본인은 자기 검토자가 될 수 없다")
        assertNull(items.single { it.subjectId == companyMember }.reviewerId, "관리자가 없으면 관리자(콘솔)가 검토한다")
        assertEquals("팀원", items.first { it.subjectId == member }.subjectName)
        assertTrue(items.all { it.decision == AccessReviewDecision.PENDING })

        val direct = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = company, includeDescendants = false), null)
        assertEquals(listOf(companyMember), reviewService.items(direct.requireId()).map { it.subjectId })
    }

    @Test
    fun `관리 콘솔 권한을 가진 사람의 권한은 조직장이 검토하지 않는다`() {
        val team = fixture.org(OrgType.TEAM)
        val manager = fixture.user("팀장").also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val adminRole = roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError()
        val admin = fixture.user("관리자").also { fixture.join(it, team) }
        assignmentService.assignDirect(admin, adminRole)
        val member = fixture.user("팀원").also { fixture.join(it, team) }
        assignmentService.assignDirect(member, fixture.role().requireId())

        val campaign = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = team), null)
        val items = reviewService.items(campaign.requireId())
        assertNull(items.single { it.subjectId == admin }.reviewerId, "관리자의 권한은 조직장이 아니라 재검토 관리자가 정한다")
        val memberItem = items.single { it.subjectId == member }
        assertEquals(manager, memberItem.reviewerId)

        // 캠페인을 만든 뒤 관리자가 되면 조직장은 결정할 수 없다
        assignmentService.assignDirect(member, adminRole)
        assertThrows<BusinessRuleException> {
            reviewService.decideAsReviewer(memberItem.requireId(), manager, AccessReviewDecision.REVOKE, null)
        }
        assertEquals(AssignmentStatus.ACTIVE, assignment(memberItem).status)
    }

    @Test
    fun `특권만·출처 조건을 지키고, 재검토 표시가 있는 할당은 그 조건과 관계없이 넣는다`() {
        val (user, companyB, _) = movedUser()
        val privileged = roleRepository.save(Role("P-${System.nanoTime()}", "특권", RoleType.PRIVILEGED, isPrivileged = true)).requireId()
        assignmentService.assignDirect(user, privileged)
        val privilegedJit = jit(user, privileged)
        val flagged = assignmentRepository.findActiveBySource(user, AssignmentSourceType.DIRECT).filter { it.reviewRequired }
        assertEquals(2, flagged.size)

        val campaign = reviewService.createCampaign(
            spec(ReviewScopeType.ORGANIZATION, orgId = companyB, privilegedOnly = true, sources = setOf(AssignmentSourceType.JIT)), null,
        )

        assertEquals(
            (flagged.map { it.requireId() } + privilegedJit.requireId()).toSet(),
            reviewService.items(campaign.requireId()).map { it.assignmentId }.toSet(),
        )

        val byRole = reviewService.createCampaign(spec(ReviewScopeType.ROLE, roleId = privileged), null)
        assertEquals(setOf(AssignmentSourceType.DIRECT, AssignmentSourceType.JIT), reviewService.items(byRole.requireId()).map { it.sourceType }.toSet())
        assertTrue(reviewService.items(byRole.requireId()).all { it.roleId == privileged && it.isPrivileged })

        assertThrows<BusinessRuleException> {
            reviewService.createCampaign(spec(ReviewScopeType.ROLE, roleId = privileged, sources = setOf(AssignmentSourceType.ORGANIZATION)), null)
        }
    }

    @Test
    fun `본인 권한은 검토할 수 없고, 회수하면 PDP 가 거부하며, 유지하면 재검토 표시가 지워지고 모두 감사 기록에 남는다`() {
        val (user, companyB, manager) = movedUser()
        val resource = fixture.resource().requireId()
        val allowing = fixture.roleAllowing(resource).requireId()
        val revokeTarget = assignmentService.assignDirect(user, allowing)
        assertEquals(Decision.ALLOW, decide(user, resource))
        val campaign = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = companyB), null)
        val items = reviewService.items(campaign.requireId())
        val revokeItem = items.single { it.assignmentId == revokeTarget.requireId() }
        val keepItem = items.first { it.reviewRequired }
        assertEquals(manager, revokeItem.reviewerId)

        assertThrows<BusinessRuleException> { reviewService.decide(revokeItem.requireId(), user, AccessReviewDecision.KEEP, null) }
        assertThrows<NotFoundException> { reviewService.decideAsReviewer(revokeItem.requireId(), fixture.user(), AccessReviewDecision.KEEP, null) }

        reviewService.decideAsReviewer(revokeItem.requireId(), manager, AccessReviewDecision.REVOKE, "퇴직 예정 업무 종료")
        reviewService.decideAsReviewer(keepItem.requireId(), manager, AccessReviewDecision.KEEP, "현 업무에 필요")

        assertEquals(AssignmentStatus.REVOKED, revokeTarget.status)
        assertEquals(Decision.DENY, decide(user, resource))
        assertFalse(assignment(keepItem).reviewRequired)
        assertEquals(AccessReviewDecision.REVOKE, revokeItem.decision)
        assertEquals(manager, revokeItem.decidedBy)
        assertThrows<BusinessRuleException> { reviewService.decideAsReviewer(keepItem.requireId(), manager, AccessReviewDecision.REVOKE, null) }

        val historyTypes = jdbc.queryForList(
            "SELECT change_type FROM role_change_history WHERE assignment_id = ? ORDER BY history_id", String::class.java, keepItem.assignmentId,
        )
        assertEquals("REVIEW", historyTypes.last(), "유지 확인이 재검토 이력으로 남는다: $historyTypes")
        assertEquals(listOf("REVIEW_REVOKE"), auditActions("ACCESS_REVIEW_ITEM", revokeItem.requireId()))
        assertEquals(listOf("REVIEW_KEEP"), auditActions("ACCESS_REVIEW_ITEM", keepItem.requireId()))
        assertEquals(listOf("REVIEW_CAMPAIGN_CREATE"), auditActions("ACCESS_REVIEW_CAMPAIGN", campaign.requireId()))
        val reason = jdbc.queryForObject(
            "SELECT reason FROM audit_event WHERE resource_type = 'ACCESS_REVIEW_ITEM' AND resource_id = ?", String::class.java, revokeItem.requireId().toString(),
        )
        assertEquals("퇴직 예정 업무 종료", reason)
    }

    @Test
    fun `JIT·위임 할당은 각자의 절차로 회수된다`() {
        val team = fixture.org(OrgType.TEAM)
        val manager = fixture.user().also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val user = fixture.user().also { fixture.join(it, team) }
        val jit = jit(user, fixture.role().requireId())
        val delegatedRole = fixture.role().requireId()
        val delegator = fixture.user().also { assignmentService.assignDirect(it, delegatedRole) }
        val delegation = delegationService.delegate(delegator, user, delegatedRole, fixture.globalScopeId(), now, now.plusSeconds(3600), "휴가 대리")
        val campaign = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = team), null)

        reviewService.items(campaign.requireId()).filter { it.subjectId == user }
            .forEach { reviewService.decideAsReviewer(it.requireId(), manager, AccessReviewDecision.REVOKE, null) }

        assertEquals(AssignmentStatus.REVOKED, jit.status)
        assertEquals(DelegationStatus.REVOKED, delegationRepository.findById(delegation.requireId()).orElseThrow().status)
        assertEquals(emptyList(), assignmentService.effectiveAssignments(user))
    }

    @Test
    fun `마감하면 남은 항목에 기한 경과 처리를 적용하고 닫는다`() {
        val team = fixture.org(OrgType.TEAM)
        val user = fixture.user().also { fixture.join(it, team) }
        val assignment = assignmentService.assignDirect(user, fixture.role().requireId())
        val campaign = reviewService.createCampaign(spec(ReviewScopeType.ORGANIZATION, orgId = team, onOverdue = AccessReviewDecision.REVOKE), null)
        val admin = fixture.user()

        reviewService.closeCampaign(campaign.requireId(), admin)

        val item = reviewService.items(campaign.requireId()).single()
        assertEquals(AccessReviewDecision.REVOKE, item.decision)
        assertNull(item.decidedBy)
        assertEquals(AssignmentStatus.REVOKED, assignment.status)
        assertEquals(AccessReviewStatus.CLOSED, campaign.status)
        assertThrows<BusinessRuleException> { reviewService.decide(item.requireId(), admin, AccessReviewDecision.KEEP, null) }
        assertEquals(listOf("REVIEW_CAMPAIGN_CREATE", "REVIEW_CAMPAIGN_CLOSE"), auditActions("ACCESS_REVIEW_CAMPAIGN", campaign.requireId()))
    }

    // ---------- API ----------

    @Test
    fun `관리 API 로 만들고 검토자는 본인 할 일만 결정하며 증적을 CSV 로 내려받는다`() {
        val admin = admin()
        val team = fixture.org(OrgType.TEAM)
        val manager = fixture.user("팀장").also { membershipService.join(it, team, MembershipType.PRIMARY, isManager = true) }
        val user = fixture.user("검토 대상").also { fixture.join(it, team) }
        val keepAssignment = assignmentService.assignDirect(user, fixture.role().requireId())
        val revokeAssignment = assignmentService.assignDirect(user, fixture.role().requireId())
        val managerAssignment = assignmentService.assignDirect(manager, fixture.role().requireId())
        val due = now.plus(Duration.ofDays(14))

        val created = json(
            post("/api/v1/access-reviews"), admin,
            """{"name":"2026 하반기 정기 점검","scopeType":"ORGANIZATION","scopeOrgId":$team,"dueAt":"$due","onOverdue":"KEEP"}""",
        ).andExpect(status().isCreated).andReturn().response.contentAsString
        val campaignId = Regex("\"id\":(\\d+)").find(created)?.groupValues?.get(1)?.toLong() ?: throw AssertionError(created)
        val items = reviewService.items(campaignId).associateBy { it.assignmentId }
        val keepItem = items.getValue(keepAssignment.requireId())
        val revokeItem = items.getValue(revokeAssignment.requireId())
        val managerItem = items.getValue(managerAssignment.requireId())

        mockMvc.perform(get("/api/v1/me/access-reviews").with(user(manager)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.length()").value(2))
            .andExpect(jsonPath("$.data[0].campaignName").value("2026 하반기 정기 점검"))
        json(post("/api/v1/me/access-review-items/${managerItem.requireId()}/decide"), manager, """{"decision":"KEEP"}""")
            .andExpect(status().isNotFound)
        json(post("/api/v1/me/access-review-items/${keepItem.requireId()}/decide"), fixture.user(), """{"decision":"KEEP"}""")
            .andExpect(status().isNotFound)
        json(post("/api/v1/me/access-review-items/${keepItem.requireId()}/decide"), manager, """{"decision":"KEEP","comment":"필요"}""")
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.decision").value("KEEP"))
            .andExpect(jsonPath("$.data.decidedByName").value("팀장"))
        json(post("/api/v1/me/access-review-items/${revokeItem.requireId()}/decide"), manager, """{"decision":"REVOKE","comment":"=업무 종료"}""")
            .andExpect(status().isOk)
        assertEquals(AssignmentStatus.REVOKED, revokeAssignment.status)
        // 검토자가 없는 항목(팀장 본인)은 관리자가 정한다
        json(post("/api/v1/access-review-items/${managerItem.requireId()}/decide"), admin, """{"decision":"KEEP"}""")
            .andExpect(status().isOk)

        mockMvc.perform(get("/api/v1/access-reviews").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.campaignId == $campaignId)].kept").value(2))
            .andExpect(jsonPath("$.data[?(@.campaignId == $campaignId)].revoked").value(1))
            .andExpect(jsonPath("$.data[?(@.campaignId == $campaignId)].pending").value(0))
        mockMvc.perform(get("/api/v1/access-reviews/$campaignId").param("decision", "REVOKE").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.campaign.total").value(3))
            .andExpect(jsonPath("$.data.items.length()").value(1))
            .andExpect(jsonPath("$.data.items[0].comment").value("=업무 종료"))

        val csv = mockMvc.perform(get("/api/v1/access-reviews/$campaignId/export").with(user(admin)))
            .andExpect(status().isOk)
            .andReturn().response.contentAsByteArray
        assertTrue(csv.take(3) == listOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte()), "Excel 용 UTF-8 BOM")
        val text = String(csv, StandardCharsets.UTF_8)
        assertTrue(text.contains("검토 대상"))
        assertTrue(text.contains(",유지,팀장,"))
        assertTrue(text.contains(",회수,팀장,"))
        assertTrue(text.contains("'=업무 종료"), "수식으로 해석될 값은 막는다")

        mockMvc.perform(post("/api/v1/access-reviews/$campaignId/close").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.status").value("CLOSED"))
    }

    @Test
    fun `REVIEW 권한이 없으면 캠페인 API 를 쓸 수 없다`() {
        val plain = fixture.user()

        mockMvc.perform(get("/api/v1/access-reviews").with(user(plain))).andExpect(status().isForbidden)
        json(
            post("/api/v1/access-reviews"), plain,
            """{"name":"x","scopeType":"ALL","dueAt":"${now.plusSeconds(3600)}"}""",
        ).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/access-reviews/1/export").with(user(plain))).andExpect(status().isForbidden)
        json(post("/api/v1/access-review-items/1/decide"), plain, """{"decision":"KEEP"}""").andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/me/access-reviews").with(user(plain))).andExpect(status().isOk)
    }

    // ---------- 도우미 ----------

    /** companyA 팀에서 companyB 팀으로 전적한 사용자. 전체 범위 직접 할당 2건이 재검토 표시를 받는다. companyB 팀에는 관리자가 있다 */
    private fun movedUser(): Triple<Long, Long, Long> {
        val group = fixture.org(OrgType.GROUP)
        val teamA = fixture.org(OrgType.TEAM, fixture.org(OrgType.COMPANY, group))
        val companyB = fixture.org(OrgType.COMPANY, group)
        val teamB = fixture.org(OrgType.TEAM, companyB)
        val manager = fixture.user("팀장").also { membershipService.join(it, teamB, MembershipType.PRIMARY, isManager = true) }
        val user = fixture.user("전적자").also { fixture.join(it, teamA) }
        repeat(2) { assignmentService.assignDirect(user, fixture.role().requireId()) }
        membershipService.transferPrimary(user, teamB)
        return Triple(user, companyB, manager)
    }

    private fun jit(subjectId: Long, roleId: Long): RoleAssignment {
        val request = accessRequestService.requestJit(subjectId, roleId, "점검", now, now.plusSeconds(3600))
        accessRequestService.approve(request.requireId(), fixture.user())
        return assignmentRepository.findActiveBySourceId(AssignmentSourceType.JIT, request.requireId()).single()
    }

    private fun spec(
        scopeType: ReviewScopeType,
        orgId: Long? = null,
        roleId: Long? = null,
        includeDescendants: Boolean = true,
        privilegedOnly: Boolean = false,
        sources: Set<AssignmentSourceType> = setOf(AssignmentSourceType.DIRECT, AssignmentSourceType.JIT, AssignmentSourceType.DELEGATION),
        onOverdue: AccessReviewDecision = AccessReviewDecision.KEEP,
    ) = AccessReviewSpec("정기 점검", scopeType, orgId, roleId, includeDescendants, privilegedOnly, sources, now.plus(Duration.ofDays(7)), onOverdue)

    private fun assignment(item: AccessReviewItem) = assignmentRepository.findById(item.assignmentId).orElseThrow()

    private fun decide(subjectId: Long, resourceId: Long) = pdp.decide(AuthorizationRequest(subjectId, resourceId, PermissionAction.READ)).decision

    private fun auditActions(resourceType: String, id: Long): List<String> = jdbc.queryForList(
        "SELECT action FROM audit_event WHERE resource_type = ? AND resource_id = ? ORDER BY event_id",
        String::class.java, resourceType, id.toString(),
    ).filterNotNull()

    private fun json(builder: MockHttpServletRequestBuilder, subjectId: Long, body: String) =
        mockMvc.perform(builder.with(user(subjectId)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
