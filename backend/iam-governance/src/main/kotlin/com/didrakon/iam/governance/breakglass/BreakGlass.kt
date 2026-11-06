package com.didrakon.iam.governance.breakglass

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import com.didrakon.iam.governance.event.AccessRequestChangedEvent
import com.didrakon.iam.governance.event.BreakGlassAction
import com.didrakon.iam.governance.event.BreakGlassEvent
import com.didrakon.iam.governance.request.AccessRequest
import com.didrakon.iam.governance.request.AccessRequestRepository
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.request.AccessRequestStatus
import com.didrakon.iam.governance.request.AccessRequestType
import com.didrakon.iam.identity.group.GroupMemberId
import com.didrakon.iam.identity.group.GroupMemberRepository
import com.didrakon.iam.identity.group.UserGroupRepository
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.event.EventListener
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.time.Instant

/** 비상 접근 정책. 어떤 역할을 어느 범위로, 어떤 조건에서, 최대 얼마나 쓸 수 있는지 */
@Entity
@Table(name = "break_glass_policy")
class BreakGlassPolicy(
    policyName: String,
    roleId: Long,
    scopeId: Long,
    maxDurationMinutes: Int,
    requireReason: Boolean = true,
    requireApproval: Boolean = false,
    requireMfa: Boolean = true,
    eligibleGroupId: Long? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "break_glass_policy_id")
    override val id: Long? = null

    @Column(name = "policy_name", nullable = false, length = 200)
    var policyName: String = policyName
        protected set

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Column(name = "require_reason", nullable = false)
    var requireReason: Boolean = requireReason
        protected set

    /** true 면 승인(JIT 와 같은 절차) 후에 세션이 시작된다 */
    @Column(name = "require_approval", nullable = false)
    var requireApproval: Boolean = requireApproval
        protected set

    /** true 면 MFA 를 거친 로그인 세션에서만 시작할 수 있다 */
    @Column(name = "require_mfa", nullable = false)
    var requireMfa: Boolean = requireMfa
        protected set

    @Column(name = "max_duration_minutes", nullable = false)
    var maxDurationMinutes: Int = maxDurationMinutes
        protected set

    /** 이 그룹의 구성원만 시작·요청할 수 있다. 비어 있으면 활성 사용자 누구나 */
    @Column(name = "eligible_group_id")
    var eligibleGroupId: Long? = eligibleGroupId
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    /** 역할·범위는 바꾸지 않는다 (진행 중인 세션·승인 대기 요청이 가리킨다). 바꾸려면 새 정책을 만들고 이 정책을 끈다 */
    internal fun update(
        policyName: String,
        maxDurationMinutes: Int,
        requireReason: Boolean,
        requireApproval: Boolean,
        requireMfa: Boolean,
        eligibleGroupId: Long?,
    ) {
        this.policyName = policyName
        this.eligibleGroupId = eligibleGroupId
        this.maxDurationMinutes = maxDurationMinutes
        this.requireReason = requireReason
        this.requireApproval = requireApproval
        this.requireMfa = requireMfa
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    internal fun snapshot(): Map<String, Any?> = mapOf(
        "policyName" to policyName, "maxDurationMinutes" to maxDurationMinutes, "requireReason" to requireReason,
        "requireApproval" to requireApproval, "requireMfa" to requireMfa, "eligibleGroupId" to eligibleGroupId,
    )

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

@Entity
@Table(name = "break_glass_session")
class BreakGlassSession(
    breakGlassPolicyId: Long,
    subjectId: Long,
    requestId: Long?,
    reason: String?,
    startTime: Instant,
    endTime: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "break_glass_session_id")
    override val id: Long? = null

    @Column(name = "break_glass_policy_id", nullable = false, updatable = false)
    val breakGlassPolicyId: Long = breakGlassPolicyId

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "request_id", updatable = false)
    val requestId: Long? = requestId

    /** 이 세션으로 생긴 ROLE_ASSIGNMENT */
    @Column(name = "assignment_id")
    var assignmentId: Long? = null
        protected set

    @Column(name = "reason", length = 1000, updatable = false)
    val reason: String? = reason

    @Column(name = "start_time", nullable = false, updatable = false)
    val startTime: Instant = startTime

    @Column(name = "end_time", nullable = false)
    var endTime: Instant = endTime
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: BreakGlassStatus = BreakGlassStatus.ACTIVE
        protected set

    @Column(name = "revoked_by")
    var revokedBy: Long? = null
        protected set

    internal fun link(assignmentId: Long) {
        this.assignmentId = assignmentId
    }

    internal fun end(by: Long?, at: Instant) {
        if (status != BreakGlassStatus.ACTIVE) throw BusinessRuleException("이미 끝난 비상 접근입니다: $id ($status)")
        status = BreakGlassStatus.REVOKED
        revokedBy = by
        endTime = minOf(endTime, at)
    }

    internal fun expire() {
        status = BreakGlassStatus.EXPIRED
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class BreakGlassStatus { ACTIVE, EXPIRED, REVOKED }

interface BreakGlassPolicyRepository : JpaRepository<BreakGlassPolicy, Long> {
    fun findByIsActiveTrue(): List<BreakGlassPolicy>

    /** 승인 없이 바로 시작하는 정책이 이 역할을 주는지 (켜진 것·꺼진 것 모두) */
    fun existsByRoleIdAndRequireApprovalFalse(roleId: Long): Boolean
}

interface BreakGlassSessionRepository : JpaRepository<BreakGlassSession, Long> {
    fun findByStatus(status: BreakGlassStatus): List<BreakGlassSession>

    fun findTop100ByOrderByStartTimeDesc(): List<BreakGlassSession>

    fun findBySubjectIdOrderByStartTimeDesc(subjectId: Long): List<BreakGlassSession>

    fun findByRequestId(requestId: Long): BreakGlassSession?
}

/** 시작 결과. 승인이 필요하면 세션 대신 승인 대기 요청이 생긴다 */
data class BreakGlassActivation(val session: BreakGlassSession?, val pendingRequest: AccessRequest?)

/**
 * 비상 접근(Break-glass). 정책의 역할을 최대 시간 동안 ROLE_ASSIGNMENT(source_type=BREAK_GLASS)로 준다.
 * 직무 분리 검사는 건너뛰는 대신 모든 시작·종료를 [BreakGlassEvent] 와 역할 변경 이력으로 남긴다.
 */
@Service
@Transactional
class BreakGlassService(
    private val policyRepository: BreakGlassPolicyRepository,
    private val sessionRepository: BreakGlassSessionRepository,
    private val requestRepository: AccessRequestRepository,
    private val accessRequestService: AccessRequestService,
    private val assignmentService: RoleAssignmentService,
    private val groupRepository: UserGroupRepository,
    private val groupMemberRepository: GroupMemberRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    fun createPolicy(
        policyName: String,
        roleId: Long,
        scopeId: Long,
        maxDurationMinutes: Int,
        requireReason: Boolean,
        requireApproval: Boolean,
        requireMfa: Boolean,
        eligibleGroupId: Long? = null,
    ): BreakGlassPolicy {
        if (maxDurationMinutes !in 1..MAX_DURATION_MINUTES) throw BusinessRuleException("최대 사용 시간은 1~${MAX_DURATION_MINUTES}분입니다")
        requireActiveGroup(eligibleGroupId)
        return policyRepository.save(
            BreakGlassPolicy(policyName, roleId, scopeId, maxDurationMinutes, requireReason, requireApproval, requireMfa, eligibleGroupId),
        )
    }

    fun updatePolicy(
        policyId: Long,
        policyName: String,
        maxDurationMinutes: Int,
        requireReason: Boolean,
        requireApproval: Boolean,
        requireMfa: Boolean,
        eligibleGroupId: Long? = null,
    ): BreakGlassPolicy {
        if (maxDurationMinutes !in 1..MAX_DURATION_MINUTES) throw BusinessRuleException("최대 사용 시간은 1~${MAX_DURATION_MINUTES}분입니다")
        val policy = findPolicy(policyId)
        // 이미 지정된 그룹이 나중에 꺼졌더라도 그대로 저장은 할 수 있게, 바꿀 때만 확인한다
        if (eligibleGroupId != policy.eligibleGroupId) requireActiveGroup(eligibleGroupId)
        val before = policy.snapshot()
        policy.update(policyName, maxDurationMinutes, requireReason, requireApproval, requireMfa, eligibleGroupId)
        eventPublisher.publishEvent(AdminChangeEvent(AUDIT_TARGET, policyId, "UPDATE", before, policy.snapshot()))
        return policy
    }

    /** 끈 정책으로는 새로 시작할 수 없다. 이미 열린 세션은 그대로 두니 필요하면 따로 끝낸다 */
    fun changePolicyActive(policyId: Long, active: Boolean): BreakGlassPolicy {
        val policy = findPolicy(policyId)
        if (policy.isActive == active) return policy
        policy.changeActive(active)
        eventPublisher.publishEvent(
            AdminChangeEvent(AUDIT_TARGET, policyId, if (active) "ACTIVATE" else "DEACTIVATE", mapOf("isActive" to !active), mapOf("isActive" to active)),
        )
        return policy
    }

    @Transactional(readOnly = true)
    fun policies(): List<BreakGlassPolicy> = policyRepository.findAll().sortedBy { it.id }

    @Transactional(readOnly = true)
    fun activePolicies(): List<BreakGlassPolicy> = policyRepository.findByIsActiveTrue().sortedBy { it.id }

    /** 이 사람이 시작할 수 있는 켜진 정책 (대상 그룹이 있으면 그 구성원일 때만) */
    @Transactional(readOnly = true)
    fun activePoliciesFor(subjectId: Long): List<BreakGlassPolicy> = activePolicies().filter { isEligible(it, subjectId) }

    /**
     * 대상 그룹이 없으면 누구나, 있으면 켜진 그룹의 지금 유효한 구성원만.
     * 그룹이 꺼져 있으면 아무도 쓸 수 없다 (그룹을 끈 것을 "누구나"로 풀지 않는다)
     */
    @Transactional(readOnly = true)
    fun isEligible(policy: BreakGlassPolicy, subjectId: Long): Boolean {
        val groupId = policy.eligibleGroupId ?: return true
        if (groupRepository.findByIdOrNull(groupId)?.isActive != true) return false
        val member = groupMemberRepository.findByIdOrNull(GroupMemberId(groupId, subjectId)) ?: return false
        val now = clock.instant()
        return !member.validFrom.isAfter(now) && member.validUntil?.isAfter(now) ?: true
    }

    /** 진행 중인 세션 전부와 최근 세션 100건 (시작 시각 역순) */
    @Transactional(readOnly = true)
    fun sessions(): List<BreakGlassSession> =
        (sessionRepository.findByStatus(BreakGlassStatus.ACTIVE) + sessionRepository.findTop100ByOrderByStartTimeDesc())
            .distinctBy { it.id }.sortedByDescending { it.startTime }

    @Transactional(readOnly = true)
    fun sessionsOf(subjectId: Long): List<BreakGlassSession> = sessionRepository.findBySubjectIdOrderByStartTimeDesc(subjectId)

    /** 본인이 연 비상 접근만 스스로 끝낼 수 있다 */
    fun endOwn(sessionId: Long, subjectId: Long) {
        val session = sessionRepository.findByIdOrNull(sessionId) ?: throw NotFoundException("비상 접근", sessionId)
        if (session.subjectId != subjectId) throw BusinessRuleException("본인의 비상 접근만 끝낼 수 있습니다")
        end(sessionId, subjectId)
    }

    /** [mfaVerified] 는 호출 측(로그인 세션·토큰의 amr)이 확인한 값이다 */
    fun activate(subjectId: Long, policyId: Long, reason: String?, mfaVerified: Boolean): BreakGlassActivation {
        val policy = policyRepository.findByIdOrNull(policyId)?.takeIf { it.isActive } ?: throw NotFoundException("비상 접근 정책", policyId)
        if (policy.requireReason && reason.isNullOrBlank()) throw BusinessRuleException("비상 접근 사유가 필요합니다")
        if (policy.requireMfa && !mfaVerified) throw BusinessRuleException("비상 접근은 MFA 를 거친 로그인에서만 시작할 수 있습니다")
        if (!isEligible(policy, subjectId)) throw BusinessRuleException("이 비상 접근 정책을 쓸 수 있는 그룹의 구성원이 아닙니다")

        val end = clock.instant().plus(Duration.ofMinutes(policy.maxDurationMinutes.toLong()))
        if (policy.requireApproval) {
            val request = accessRequestService.createBreakGlassRequest(subjectId, policy.roleId, policy.scopeId, reason.orEmpty().ifBlank { "비상 접근" }, end)
            return BreakGlassActivation(null, request)
        }
        return BreakGlassActivation(start(policy, subjectId, null, reason), null)
    }

    /** 승인 대기 중이던 비상 접근이 승인되면 그때부터 최대 시간만큼 세션을 연다 */
    @EventListener
    fun onAccessRequestChanged(event: AccessRequestChangedEvent) {
        if (event.requestType != AccessRequestType.BREAK_GLASS || event.status != AccessRequestStatus.APPROVED) return
        val request = requestRepository.findByIdOrNull(event.requestId) ?: return
        val policy = policyRepository.findAll().firstOrNull { it.isActive && it.roleId == request.roleId && it.scopeId == request.scopeId }
            ?: throw BusinessRuleException("이 요청의 비상 접근 정책이 꺼져 있어 승인할 수 없습니다. 반려하세요: ${event.requestId}")
        if (!isEligible(policy, request.subjectId)) {
            throw BusinessRuleException("요청자가 이 비상 접근 정책을 쓸 수 있는 그룹의 구성원이 아니어서 승인할 수 없습니다. 반려하세요: ${event.requestId}")
        }
        start(policy, request.subjectId, request.requireId(), request.reason)
    }

    fun end(sessionId: Long, endedBy: Long?) {
        val session = sessionRepository.findByIdOrNull(sessionId) ?: throw NotFoundException("비상 접근", sessionId)
        session.end(endedBy, clock.instant())
        assignmentService.revokeForSource(AssignmentSourceType.BREAK_GLASS, sessionId, endedBy, "비상 접근 종료")
        publish(session, BreakGlassAction.END, endedBy, null)
    }

    /** 최대 시간이 지난 세션을 EXPIRED 로 바꾼다 (할당은 기간이 지나 이미 판정에서 빠진다) */
    fun expireDue(): Int {
        val now = clock.instant()
        val due = sessionRepository.findByStatus(BreakGlassStatus.ACTIVE).filter { !it.endTime.isAfter(now) }
        due.forEach {
            it.expire()
            publish(it, BreakGlassAction.EXPIRE, null, null)
        }
        return due.size
    }

    private fun start(policy: BreakGlassPolicy, subjectId: Long, requestId: Long?, reason: String?): BreakGlassSession {
        val now = clock.instant()
        val session = sessionRepository.save(
            BreakGlassSession(policy.requireId(), subjectId, requestId, reason, now, now.plus(Duration.ofMinutes(policy.maxDurationMinutes.toLong()))),
        )
        val assignment = assignmentService.grantForSource(
            subjectId, policy.roleId, policy.scopeId, AssignmentSourceType.BREAK_GLASS, session.requireId(),
            now, session.endTime, subjectId, reason ?: "비상 접근",
        )
        session.link(assignment.requireId())
        publish(session, BreakGlassAction.ACTIVATE, subjectId, reason)
        return session
    }

    private fun publish(session: BreakGlassSession, action: BreakGlassAction, actorId: Long?, reason: String?) {
        val roleId = policyRepository.findByIdOrNull(session.breakGlassPolicyId)?.roleId ?: return
        eventPublisher.publishEvent(BreakGlassEvent(session.requireId(), session.subjectId, roleId, action, actorId, reason))
    }

    private fun requireActiveGroup(groupId: Long?) {
        if (groupId == null) return
        val group = groupRepository.findByIdOrNull(groupId) ?: throw NotFoundException("그룹", groupId)
        if (!group.isActive) throw BusinessRuleException("꺼진 그룹은 대상으로 지정할 수 없습니다: ${group.groupCode}")
    }

    private fun findPolicy(policyId: Long): BreakGlassPolicy =
        policyRepository.findByIdOrNull(policyId) ?: throw NotFoundException("비상 접근 정책", policyId)

    companion object {
        const val MAX_DURATION_MINUTES = 24 * 60
        private const val AUDIT_TARGET = "BREAK_GLASS_POLICY"
    }
}
