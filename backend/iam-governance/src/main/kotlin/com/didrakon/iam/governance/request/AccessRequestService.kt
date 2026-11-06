package com.didrakon.iam.governance.request

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.governance.event.AccessRequestChangedEvent
import com.didrakon.iam.governance.sod.SodGuard
import com.didrakon.iam.identity.group.GroupMemberId
import com.didrakon.iam.identity.group.GroupMemberRepository
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.risk.RiskContext
import com.didrakon.iam.risk.RiskEngine
import com.didrakon.iam.risk.RiskType
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Duration
import java.time.Instant

/**
 * JIT 접근 요청과 승인. 승인 조건([ApprovalPolicy])을 채우면 요청 기간 동안만 유효한 ROLE_ASSIGNMENT(source_type=JIT)를 만든다.
 * 승인이 필요한 Break-glass 요청도 같은 승인 절차를 거치고, 승인되면 [AccessRequestChangedEvent] 를 받아 세션이 시작된다.
 */
@Service
@Transactional
class AccessRequestService(
    private val requestRepository: AccessRequestRepository,
    private val approvalRepository: ApprovalRepository,
    private val approvalPolicyRepository: ApprovalPolicyRepository,
    private val roleRepository: RoleRepository,
    private val scopeRepository: ScopeRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val groupRepository: UserGroupRepository,
    private val groupMemberRepository: GroupMemberRepository,
    private val assignmentService: RoleAssignmentService,
    private val sodGuard: SodGuard,
    private val riskEngine: RiskEngine,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    fun requestJit(
        subjectId: Long,
        roleId: Long,
        reason: String,
        requestedStart: Instant,
        requestedEnd: Instant,
        scopeId: Long? = null,
    ): AccessRequest {
        val now = clock.instant()
        if (reason.isBlank()) throw BusinessRuleException("요청 사유가 필요합니다")
        if (!requestedEnd.isAfter(requestedStart) || !requestedEnd.isAfter(now)) throw BusinessRuleException("요청 기간이 올바르지 않습니다")
        if (Duration.between(requestedStart, requestedEnd) > MAX_JIT_DURATION) {
            throw BusinessRuleException("JIT 요청 기간은 최대 ${MAX_JIT_DURATION.toDays()}일입니다")
        }
        if (requestRepository.findBySubjectIdAndRoleIdAndStatus(subjectId, roleId, AccessRequestStatus.PENDING).isNotEmpty()) {
            throw BusinessRuleException("같은 역할로 처리 중인 요청이 있습니다")
        }
        // 승인 뒤에 막히지 않도록 직무 분리 위반은 요청 시점에 먼저 알려 준다
        if (sodGuard.violation(subjectId, roleId, requestedStart, requestedEnd) != null) throw BusinessRuleException("직무 분리 위반으로 요청할 수 없는 역할입니다")
        return create(AccessRequestType.JIT, subjectId, activeRole(roleId), scopeId, reason, requestedStart, requestedEnd)
    }

    /** Break-glass 용. 승인 조건은 JIT 와 같다 */
    internal fun createBreakGlassRequest(subjectId: Long, roleId: Long, scopeId: Long, reason: String, end: Instant): AccessRequest =
        create(AccessRequestType.BREAK_GLASS, subjectId, activeRole(roleId), scopeId, reason, clock.instant(), end)

    /** 승인 조건을 모두 채우면 APPROVED 가 되고, JIT 는 바로 역할이 부여된다 */
    fun approve(requestId: Long, approverId: Long, comment: String? = null): AccessRequest {
        val request = pending(requestId)
        val decisions = approvalRepository.findByRequestIdOrderByApprovalStepAsc(requestId)
        if (approverId == request.subjectId) throw BusinessRuleException("본인 요청은 승인할 수 없습니다")
        if (decisions.any { it.approverId == approverId }) throw BusinessRuleException("이미 결정한 요청입니다")

        val policy = policyFor(request)
        approvalRepository.save(
            Approval(requestId, approverId, policy?.id, decisions.size + 1, ApprovalStatus.APPROVED, comment, clock.instant()),
        )
        val approvers = decisions.filter { it.status == ApprovalStatus.APPROVED }.map { it.approverId } + approverId
        if (!satisfied(request, policy, approvers)) return request

        request.moveTo(AccessRequestStatus.APPROVED, clock.instant())
        if (request.requestType == AccessRequestType.JIT) {
            assignmentService.grantForSource(
                request.subjectId, request.roleId, request.scopeId, AssignmentSourceType.JIT, request.requireId(),
                maxOf(request.requestedStart, clock.instant()), request.requestedEnd, approverId, request.reason,
            )
        }
        publish(request, approverId, comment)
        return request
    }

    fun reject(requestId: Long, approverId: Long, comment: String?): AccessRequest {
        val request = pending(requestId)
        if (approverId == request.subjectId) throw BusinessRuleException("본인 요청은 반려할 수 없습니다. 취소를 쓰세요")
        val step = approvalRepository.findByRequestIdOrderByApprovalStepAsc(requestId).size + 1
        approvalRepository.save(Approval(requestId, approverId, policyFor(request)?.id, step, ApprovalStatus.REJECTED, comment, clock.instant()))
        request.moveTo(AccessRequestStatus.REJECTED, clock.instant())
        publish(request, approverId, comment)
        return request
    }

    fun cancel(requestId: Long, subjectId: Long): AccessRequest {
        val request = pending(requestId)
        if (request.subjectId != subjectId) throw BusinessRuleException("본인 요청만 취소할 수 있습니다")
        request.moveTo(AccessRequestStatus.CANCELLED, clock.instant())
        publish(request, subjectId, null)
        return request
    }

    /** 기간이 끝나도록 처리되지 않은 요청을 EXPIRED 로 바꾼다 */
    fun expirePending(): Int {
        val now = clock.instant()
        val due = requestRepository.findPendingEndedBefore(now)
        due.forEach {
            it.moveTo(AccessRequestStatus.EXPIRED, now)
            publish(it, null, "기간 종료")
        }
        return due.size
    }

    @Transactional(readOnly = true)
    fun pendingRequests(): List<AccessRequest> = requestRepository.findByStatusOrderByCreatedAtAsc(AccessRequestStatus.PENDING)

    /** 처리가 끝난 요청(승인·반려·취소·만료) 최근 200건. 요청 시각 역순 */
    @Transactional(readOnly = true)
    fun history(): List<AccessRequest> = requestRepository.findTop200ByStatusNotOrderByCreatedAtDesc(AccessRequestStatus.PENDING)

    @Transactional(readOnly = true)
    fun requestsOf(subjectId: Long): List<AccessRequest> = requestRepository.findBySubjectIdOrderByCreatedAtDesc(subjectId)

    /** 요청별 승인자 결정 (단계 순) */
    @Transactional(readOnly = true)
    fun approvalsByRequest(requestIds: Collection<Long>): Map<Long, List<Approval>> =
        if (requestIds.isEmpty()) emptyMap() else approvalRepository.findByRequestIdIn(requestIds).sortedBy { it.approvalStep }.groupBy { it.requestId }

    @Transactional(readOnly = true)
    fun approvals(requestId: Long): List<Approval> = approvalRepository.findByRequestIdOrderByApprovalStepAsc(requestId)

    private fun create(
        type: AccessRequestType,
        subjectId: Long,
        role: Role,
        scopeId: Long?,
        reason: String,
        start: Instant,
        end: Instant,
    ): AccessRequest {
        val resolvedScopeId = scopeId ?: globalScopeId()
        if (!scopeRepository.existsById(resolvedScopeId)) throw NotFoundException("scope", resolvedScopeId)
        // 위험 등급 = 역할 성격과 요청 상황 평가 중 높은 쪽. 평가는 요청과 연결해 남긴다
        val risk = riskEngine.evaluate(RiskContext(subjectId, if (type == AccessRequestType.JIT) RiskType.JIT else RiskType.PRIVILEGE))
        val request = requestRepository.save(
            AccessRequest(type, subjectId, role.requireId(), resolvedScopeId, reason, maxOf(riskOf(role), risk.level), start, end, clock.instant()),
        )
        riskEngine.record(subjectId, risk, request.requireId())
        publish(request, subjectId, reason)
        return request
    }

    private fun satisfied(request: AccessRequest, policy: ApprovalPolicy?, approvers: List<Long>): Boolean {
        val distinct = approvers.toSet()
        if (distinct.size < (policy?.requiredApprovalCount ?: DEFAULT_APPROVAL_COUNT)) return false
        if (policy?.requireSecurityTeam == true && distinct.none(::isSecurityTeam)) return false
        if (policy?.requireOwner == true && distinct.none { isManagerOf(it, request.subjectId) }) return false
        return true
    }

    /** role_type 이 같은 정책 → role_type 이 비어 있는 기본 정책 → 없으면 승인 1건 */
    private fun policyFor(request: AccessRequest): ApprovalPolicy? {
        val roleType = roleRepository.findByIdOrNull(request.roleId)?.roleType
        val policies = approvalPolicyRepository.findByIsActiveTrue()
        return policies.firstOrNull { it.roleType == roleType } ?: policies.firstOrNull { it.roleType == null }
    }

    private fun isSecurityTeam(subjectId: Long): Boolean {
        val group = groupRepository.findByGroupCode(SECURITY_TEAM_GROUP) ?: return false
        return groupMemberRepository.existsById(GroupMemberId(group.requireId(), subjectId))
    }

    private fun isManagerOf(approverId: Long, requesterId: Long): Boolean {
        val orgId = membershipRepository.findActivePrimary(requesterId)?.orgId ?: return false
        return membershipRepository.findActiveBySubjectId(approverId).any { it.orgId == orgId && it.isManager }
    }

    private fun riskOf(role: Role): RiskLevel = when {
        role.isPrivileged -> RiskLevel.HIGH
        role.isSensitive -> RiskLevel.MEDIUM
        else -> RiskLevel.LOW
    }

    private fun activeRole(roleId: Long): Role {
        val role = roleRepository.findByIdOrNull(roleId) ?: throw NotFoundException("역할", roleId)
        if (!role.isActive) throw BusinessRuleException("비활성 역할은 요청할 수 없습니다: ${role.roleCode}")
        return role
    }

    private fun pending(requestId: Long): AccessRequest {
        val request = requestRepository.findByIdOrNull(requestId) ?: throw NotFoundException("접근 요청", requestId)
        if (request.status != AccessRequestStatus.PENDING) throw BusinessRuleException("처리가 끝난 요청입니다: $requestId (${request.status})")
        return request
    }

    private fun globalScopeId(): Long =
        scopeRepository.findByScopeCode(Scope.GLOBAL_CODE)?.requireId() ?: throw IllegalStateException("GLOBAL scope 행이 없습니다")

    private fun publish(request: AccessRequest, actorId: Long?, comment: String?) {
        eventPublisher.publishEvent(
            AccessRequestChangedEvent(request.requireId(), request.requestType, request.subjectId, request.roleId, request.status, actorId, comment),
        )
    }

    companion object {
        const val SECURITY_TEAM_GROUP = "SECURITY_TEAM"
        const val DEFAULT_APPROVAL_COUNT = 1
        val MAX_JIT_DURATION: Duration = Duration.ofDays(30)
    }
}
