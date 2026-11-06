package com.didrakon.iam.governance

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.governance.breakglass.BreakGlassPolicy
import com.didrakon.iam.governance.breakglass.BreakGlassPolicyRepository
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.breakglass.BreakGlassStatus
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.delegation.DelegationStatus
import com.didrakon.iam.governance.request.AccessRequestRepository
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.request.AccessRequestStatus
import com.didrakon.iam.governance.request.ApprovalPolicy
import com.didrakon.iam.governance.request.ApprovalPolicyRepository
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Duration
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

@AuthzTest
class GovernanceTests @Autowired constructor(
    private val conflictService: RoleConflictService,
    private val accessRequestService: AccessRequestService,
    private val accessRequestRepository: AccessRequestRepository,
    private val approvalPolicyRepository: ApprovalPolicyRepository,
    private val delegationService: DelegationService,
    private val breakGlassService: BreakGlassService,
    private val breakGlassPolicyRepository: BreakGlassPolicyRepository,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val organizationRoleService: OrganizationRoleService,
    private val membershipService: MembershipService,
    private val groupRepository: UserGroupRepository,
    private val groupMemberService: GroupMemberService,
    private val groupService: GroupService,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    private val now: Instant get() = Instant.now()

    // ---------- 직무 분리 ----------

    @Test
    fun `충돌 역할을 가진 subject 에게는 직접 부여할 수 없고 승인된 예외가 있으면 허용된다`() {
        val (payment, approval) = fixture.role().requireId() to fixture.role().requireId()
        val conflict = conflictService.define(payment, approval, RiskLevel.HIGH, "지급과 승인 분리")
        val userId = fixture.user()
        assignmentService.assignDirect(userId, payment)

        assertThrows<BusinessRuleException> { assignmentService.assignDirect(userId, approval) }

        conflictService.grantException(conflict.requireId(), userId, fixture.user(), "결산 기간 한시 허용", now.plusSeconds(3600))
        assignmentService.assignDirect(userId, approval)
    }

    @Test
    fun `조직 역할로 충돌 역할이 생기면 소속 변경 자체가 취소된다`() {
        val (payment, approval) = fixture.role().requireId() to fixture.role().requireId()
        conflictService.define(payment, approval, RiskLevel.HIGH)
        val company = fixture.org(OrgType.COMPANY)
        organizationRoleService.create(company, approval)
        val userId = fixture.user()
        assignmentService.assignDirect(userId, payment)

        assertThrows<BusinessRuleException> { membershipService.join(userId, company, MembershipType.PRIMARY) }
    }

    @Test
    fun `비상 접근은 직무 분리 검사를 건너뛴다`() {
        val (payment, approval) = fixture.role().requireId() to fixture.role().requireId()
        conflictService.define(payment, approval, RiskLevel.HIGH)
        val userId = fixture.user()
        assignmentService.assignDirect(userId, payment)
        val policy = breakGlassPolicy(approval, requireMfa = false)

        val activation = breakGlassService.activate(userId, policy, "장애 대응", mfaVerified = false)

        assertNotNull(activation.session)
    }

    // ---------- JIT ----------

    @Test
    fun `JIT 요청이 승인되면 요청 기간 동안만 유효한 JIT 할당이 생긴다`() {
        val userId = fixture.user()
        val roleId = fixture.role().requireId()
        val end = now.plus(Duration.ofHours(4))
        val request = accessRequestService.requestJit(userId, roleId, "운영 DB 점검", now, end)

        assertThrows<BusinessRuleException> { accessRequestService.approve(request.requireId(), userId) }
        assertNull(request.closedAt)
        val beforeApprove = now
        accessRequestService.approve(request.requireId(), fixture.user(), "확인")

        assertEquals(AccessRequestStatus.APPROVED, request.status)
        assertClosedSince(request.closedAt, beforeApprove)
        val assignment = assignmentRepository.findActiveBySourceId(AssignmentSourceType.JIT, request.requireId()).single()
        assertEquals(roleId, assignment.roleId)
        assertEquals(end, assignment.validUntil)
        val audited = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE event_type = 'JIT' AND resource_id = ? ORDER BY event_id",
            String::class.java, request.requireId().toString(),
        )
        assertEquals(listOf("REQUEST", "APPROVED"), audited)
    }

    @Test
    fun `승인 정책이 승인 수·보안팀·소속 관리자 승인을 요구하면 모두 채워야 승인된다`() {
        val role = fixture.role()
        approvalPolicyRepository.save(ApprovalPolicy("업무 역할", RoleType.BUSINESS, requiredApprovalCount = 2, requireSecurityTeam = true, requireOwner = true))
        val team = fixture.org(OrgType.TEAM)
        val requester = fixture.user().also { fixture.join(it, team) }
        val manager = fixture.user().also { membershipService.join(it, team, MembershipType.SECONDARY, isManager = true) }
        val colleague = fixture.user()
        val securityMember = fixture.user()
        val securityTeam = groupRepository.findByGroupCode(AccessRequestService.SECURITY_TEAM_GROUP)
            ?: groupRepository.save(UserGroup(AccessRequestService.SECURITY_TEAM_GROUP, "보안팀", GroupType.STATIC))
        groupMemberService.addMember(securityTeam.requireId(), securityMember)
        val request = accessRequestService.requestJit(requester, role.requireId(), "점검", now, now.plusSeconds(3600))

        accessRequestService.approve(request.requireId(), colleague)
        accessRequestService.approve(request.requireId(), securityMember)
        assertEquals(AccessRequestStatus.PENDING, request.status)

        accessRequestService.approve(request.requireId(), manager)
        assertEquals(AccessRequestStatus.APPROVED, request.status)
        assertEquals(3, accessRequestService.approvals(request.requireId()).size)
    }

    @Test
    fun `반려·취소된 요청은 더 처리할 수 없고 기간이 지난 대기 요청은 만료된다`() {
        val userId = fixture.user()
        val started = now
        val rejected = accessRequestService.requestJit(userId, fixture.role().requireId(), "점검", now, now.plusSeconds(3600))
        accessRequestService.reject(rejected.requireId(), fixture.user(), "사유 불충분")
        assertClosedSince(rejected.closedAt, started)
        val rejectedAt = rejected.closedAt
        assertThrows<BusinessRuleException> { accessRequestService.approve(rejected.requireId(), fixture.user()) }
        assertEquals(rejectedAt, rejected.closedAt)

        val cancelled = accessRequestService.requestJit(userId, fixture.role().requireId(), "점검", now, now.plusSeconds(3600))
        assertThrows<BusinessRuleException> { accessRequestService.cancel(cancelled.requireId(), fixture.user()) }
        assertNull(cancelled.closedAt)
        accessRequestService.cancel(cancelled.requireId(), userId)
        assertEquals(AccessRequestStatus.CANCELLED, cancelled.status)
        assertClosedSince(cancelled.closedAt, started)

        val stale = accessRequestService.requestJit(userId, fixture.role().requireId(), "점검", now.minusSeconds(7200), now.plusSeconds(1))
        Thread.sleep(1100)
        val beforeExpire = now
        accessRequestService.expirePending()
        assertEquals(AccessRequestStatus.EXPIRED, stale.status)
        assertClosedSince(stale.closedAt, beforeExpire)
        // DB 에도 남는다
        accessRequestRepository.flush()
        val stored = jdbc.queryForObject("SELECT closed_at FROM access_request WHERE request_id = ?", java.sql.Timestamp::class.java, stale.requireId())
        assertNotNull(stored)
    }

    @Test
    fun `직무 분리에 걸리는 역할은 요청 단계에서 거부된다`() {
        val (payment, approval) = fixture.role().requireId() to fixture.role().requireId()
        conflictService.define(payment, approval, RiskLevel.HIGH)
        val userId = fixture.user()
        assignmentService.assignDirect(userId, payment)

        assertThrows<BusinessRuleException> { accessRequestService.requestJit(userId, approval, "필요", now, now.plusSeconds(3600)) }
    }

    // ---------- 위임 ----------

    @Test
    fun `가진 역할만 위임할 수 있고 위임받은 역할은 다시 위임할 수 없다`() {
        val roleId = fixture.role().requireId()
        val global = fixture.globalScopeId()
        val (delegator, delegate, third) = Triple(fixture.user(), fixture.user(), fixture.user())

        assertThrows<BusinessRuleException> { delegationService.delegate(delegator, delegate, roleId, global, now, now.plusSeconds(3600), "휴가") }

        assignmentService.assignDirect(delegator, roleId)
        val delegation = delegationService.delegate(delegator, delegate, roleId, global, now, now.plusSeconds(3600), "휴가")

        assertEquals(DelegationStatus.ACTIVE, delegation.status)
        assertEquals(1, assignmentRepository.findActiveBySourceId(AssignmentSourceType.DELEGATION, delegation.requireId()).size)
        assertThrows<BusinessRuleException> { delegationService.delegate(delegate, third, roleId, global, now, now.plusSeconds(3600), "재위임") }
    }

    @Test
    fun `위임자가 역할을 잃으면 위임과 대리인의 할당도 끝난다`() {
        val roleId = fixture.role().requireId()
        val (delegator, delegate) = fixture.user() to fixture.user()
        val source = assignmentService.assignDirect(delegator, roleId)
        val delegation = delegationService.delegate(delegator, delegate, roleId, fixture.globalScopeId(), now, now.plusSeconds(3600), "휴가")

        assignmentService.revoke(source.requireId())

        assertEquals(DelegationStatus.REVOKED, delegation.status)
        assertEquals(emptyList(), assignmentRepository.findActiveBySourceId(AssignmentSourceType.DELEGATION, delegation.requireId()))
    }

    @Test
    fun `시작 전 위임은 PENDING 이고 그동안 대리인의 할당은 판정에 쓰이지 않는다`() {
        val roleId = fixture.role().requireId()
        val (delegator, delegate) = fixture.user() to fixture.user()
        assignmentService.assignDirect(delegator, roleId)

        val delegation = delegationService.delegate(delegator, delegate, roleId, fixture.globalScopeId(), now.plusSeconds(3600), now.plusSeconds(7200), "출장")

        assertEquals(DelegationStatus.PENDING, delegation.status)
        assertTrue(assignmentRepository.findEffective(delegate, now).none { it.roleId == roleId })
    }

    // ---------- 비상 접근 ----------

    @Test
    fun `승인 없는 비상 접근은 바로 시작되고 종료하면 할당이 회수된다`() {
        val roleId = fixture.role().requireId()
        val policy = breakGlassPolicy(roleId, requireMfa = true)
        val userId = fixture.user()

        assertThrows<BusinessRuleException> { breakGlassService.activate(userId, policy, "장애", mfaVerified = false) }
        assertThrows<BusinessRuleException> { breakGlassService.activate(userId, policy, " ", mfaVerified = true) }
        val session = breakGlassService.activate(userId, policy, "결제 장애 대응", mfaVerified = true).session ?: throw AssertionError()

        val assignment = assignmentRepository.findById(session.assignmentId ?: throw AssertionError()).orElseThrow()
        assertEquals(AssignmentSourceType.BREAK_GLASS, assignment.sourceType)
        assertEquals(session.endTime, assignment.validUntil)

        breakGlassService.end(session.requireId(), userId)
        assertEquals(BreakGlassStatus.REVOKED, session.status)
        assertEquals(AssignmentStatus.REVOKED, assignment.status)
    }

    @Test
    fun `승인이 필요한 비상 접근은 승인되어야 세션이 열린다`() {
        val roleId = fixture.role().requireId()
        val policy = breakGlassPolicy(roleId, requireMfa = false, requireApproval = true)
        val userId = fixture.user()

        val activation = breakGlassService.activate(userId, policy, "데이터 복구", mfaVerified = false)
        assertNull(activation.session)
        val request = activation.pendingRequest ?: throw AssertionError()
        assertTrue(assignmentRepository.findEffective(userId, now).none { it.roleId == roleId })

        accessRequestService.approve(request.requireId(), fixture.user())

        assertTrue(assignmentRepository.findEffective(userId, Instant.now()).any { it.roleId == roleId && it.sourceType == AssignmentSourceType.BREAK_GLASS })
    }

    // ---------- 만료 ----------

    @Test
    fun `기간이 끝난 할당은 EXPIRED 가 되고 그 역할로 한 위임도 끝난다`() {
        val roleId = fixture.role().requireId()
        val (delegator, delegate) = fixture.user() to fixture.user()
        val source = assignmentService.assignDirect(delegator, roleId, validUntil = now.plusSeconds(1))
        val delegation = delegationService.delegate(delegator, delegate, roleId, fixture.globalScopeId(), now, now.plusSeconds(3600), "휴가")
        Thread.sleep(1100)

        assignmentService.expireDue()

        assertEquals(AssignmentStatus.EXPIRED, source.status)
        assertEquals(DelegationStatus.REVOKED, delegation.status)
        assertFalse(assignmentRepository.findEffective(delegate, Instant.now()).any { it.roleId == roleId })
    }

    // ---------- 비상 접근 대상 그룹 ----------

    @Test
    fun `대상 그룹이 있는 비상 접근은 그 그룹의 유효한 구성원만 시작하고, 그룹이 없으면 누구나 시작한다`() {
        val roleId = fixture.role().requireId()
        val group = groupRepository.save(UserGroup("BG-${System.nanoTime()}", "당직", GroupType.STATIC)).requireId()
        val member = fixture.user().also { groupMemberService.addMember(group, it) }
        val outsider = fixture.user()
        val restricted = breakGlassService.createPolicy("당직 비상", roleId, fixture.globalScopeId(), 60, true, false, false, group)
        val open = breakGlassService.createPolicy("모두 비상", fixture.role().requireId(), fixture.globalScopeId(), 60, true, false, false)

        val denied = assertThrows<BusinessRuleException> { breakGlassService.activate(outsider, restricted.requireId(), "장애", mfaVerified = true) }
        assertTrue(denied.message.orEmpty().contains("그룹"), denied.message)
        assertTrue(assignmentRepository.findEffective(outsider, now).none { it.roleId == roleId })
        assertFalse(breakGlassService.activePoliciesFor(outsider).any { it.id == restricted.id })
        assertTrue(breakGlassService.activePoliciesFor(outsider).any { it.id == open.id })
        assertNotNull(breakGlassService.activate(outsider, open.requireId(), "장애", mfaVerified = true).session)

        assertTrue(breakGlassService.activePoliciesFor(member).any { it.id == restricted.id })
        assertNotNull(breakGlassService.activate(member, restricted.requireId(), "장애", mfaVerified = true).session)

        // 구성원에서 빠지면 더는 시작할 수 없다
        groupMemberService.removeMember(group, member)
        assertThrows<BusinessRuleException> { breakGlassService.activate(member, restricted.requireId(), "장애", mfaVerified = true) }
    }

    @Test
    fun `승인이 필요한 비상 접근도 대상 그룹 구성원만 요청할 수 있고, 승인 전에 그룹에서 빠지면 승인할 수 없다`() {
        val roleId = fixture.role().requireId()
        val group = groupRepository.save(UserGroup("BG-${System.nanoTime()}", "당직", GroupType.STATIC)).requireId()
        val member = fixture.user().also { groupMemberService.addMember(group, it) }
        val policy = breakGlassService.createPolicy("승인 비상", roleId, fixture.globalScopeId(), 60, true, true, false, group).requireId()

        assertThrows<BusinessRuleException> { breakGlassService.activate(fixture.user(), policy, "장애", mfaVerified = true) }
        val request = breakGlassService.activate(member, policy, "장애", mfaVerified = true).pendingRequest ?: throw AssertionError()
        groupMemberService.removeMember(group, member)

        assertThrows<BusinessRuleException> { accessRequestService.approve(request.requireId(), fixture.user()) }
        assertTrue(assignmentRepository.findEffective(member, now).none { it.roleId == roleId })
    }

    @Test
    fun `꺼진 그룹이나 없는 그룹은 대상으로 지정할 수 없다`() {
        val roleId = fixture.role().requireId()
        val group = groupRepository.save(UserGroup("BG-${System.nanoTime()}", "당직", GroupType.STATIC))
        val off = groupRepository.save(UserGroup("BG-OFF-${System.nanoTime()}", "꺼진 그룹", GroupType.STATIC))
        groupService.changeActive(off.requireId(), false)

        assertThrows<BusinessRuleException> { breakGlassService.createPolicy("x", roleId, fixture.globalScopeId(), 60, true, false, false, off.requireId()) }
        assertThrows<NotFoundException> {
            breakGlassService.createPolicy("x", roleId, fixture.globalScopeId(), 60, true, false, false, Long.MAX_VALUE)
        }
        val policy = breakGlassService.createPolicy("x", roleId, fixture.globalScopeId(), 60, true, false, false, group.requireId())
        breakGlassService.updatePolicy(policy.requireId(), "x", 60, true, false, false, null)
        assertNull(policy.eligibleGroupId)
    }

    private fun assertClosedSince(closedAt: Instant?, since: Instant) {
        assertNotNull(closedAt)
        assertFalse(closedAt.isBefore(since.minusMillis(1)), "closedAt=$closedAt since=$since")
        assertFalse(closedAt.isAfter(Instant.now()), "closedAt=$closedAt")
    }

    private fun breakGlassPolicy(roleId: Long, requireMfa: Boolean, requireApproval: Boolean = false): Long =
        breakGlassPolicyRepository.save(
            BreakGlassPolicy("비상", roleId, fixture.globalScopeId(), maxDurationMinutes = 60, requireApproval = requireApproval, requireMfa = requireMfa),
        ).requireId()
}
