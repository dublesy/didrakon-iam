package com.didrakon.iam.api.governance

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.governance.breakglass.BreakGlassPolicy
import com.didrakon.iam.governance.breakglass.BreakGlassPolicyRepository
import com.didrakon.iam.governance.breakglass.BreakGlassSession
import com.didrakon.iam.governance.delegation.Delegation
import com.didrakon.iam.governance.request.AccessRequest
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserRepository
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Instant

/** 승인자 한 명의 결정 */
data class ApprovalView(val approverId: Long, val approverName: String?, val status: String, val comment: String?, val decidedAt: Instant)

/** 접근 요청 + 화면에 보여줄 이름과 승인자 결정 */
data class AccessRequestView(
    val requestId: Long,
    val requestType: String,
    val subjectId: Long,
    val subjectName: String?,
    val roleId: Long,
    val roleName: String?,
    val scopeId: Long,
    val scopeCode: String?,
    val reason: String,
    val riskLevel: RiskLevel,
    val requestedStart: Instant,
    val requestedEnd: Instant,
    val status: String,
    val createdAt: Instant,
    val decisions: List<ApprovalView>,
    /** 처리가 끝난 시각. 대기 중이거나 예전에 끝난 요청은 비어 있다 */
    val closedAt: Instant?,
)

data class BreakGlassPolicyResponse(
    val policyId: Long,
    val policyName: String,
    val roleId: Long,
    val roleName: String?,
    val scopeId: Long,
    val scopeCode: String?,
    val maxDurationMinutes: Int,
    val requireReason: Boolean,
    val requireApproval: Boolean,
    val requireMfa: Boolean,
    val isActive: Boolean,
    /** 시작할 수 있는 그룹. 비어 있으면 누구나 */
    val eligibleGroupId: Long?,
    val eligibleGroupCode: String?,
    val eligibleGroupName: String?,
)

/** 비상 접근 대상 그룹 선택지. 그룹 관리 권한이 없는 비상 접근 관리자도 고를 수 있게 따로 준다 */
data class GroupOption(val groupId: Long, val groupCode: String, val groupName: String)

/** revokedBy 가 있으면 그 사람이 끝냈고, 없으면 최대 시간이 지나 끝났다 */
data class BreakGlassSessionResponse(
    val sessionId: Long,
    val policyId: Long,
    val policyName: String?,
    val subjectId: Long,
    val subjectName: String?,
    val roleId: Long?,
    val roleName: String?,
    val reason: String?,
    val startTime: Instant,
    val endTime: Instant,
    val status: String,
    val requestId: Long?,
    val revokedBy: Long?,
    val revokedByName: String?,
)

data class DelegationResponse(
    val delegationId: Long,
    val delegatorId: Long,
    val delegatorName: String?,
    val delegateId: Long,
    val delegateName: String?,
    val roleId: Long,
    val roleName: String?,
    val scopeId: Long,
    val scopeCode: String?,
    val startTime: Instant,
    val endTime: Instant,
    val reason: String,
    val status: String,
    val createdAt: Instant,
)

data class MyDelegationsResponse(val given: List<DelegationResponse>, val received: List<DelegationResponse>)

data class RoleOption(val roleId: Long, val roleCode: String, val roleName: String, val isPrivileged: Boolean)

data class ScopeOption(val scopeId: Long, val scopeCode: String, val scopeName: String)

/** 본인이 직접 가져(위임받지 않아) 위임할 수 있는 역할·범위 */
data class DelegatableRole(val roleId: Long, val roleName: String, val scopeId: Long, val scopeCode: String)

/** 본인 권한 요청·위임 화면의 선택지. 요청할 수 있는 역할(사용 중), 범위(사용 중), 위임할 수 있는 역할 */
data class AccessOptionsResponse(val roles: List<RoleOption>, val scopes: List<ScopeOption>, val delegatable: List<DelegatableRole>)

/** 위임 대상을 사번으로 찾은 결과. 이름 외의 정보는 주지 않는다 */
data class PersonResponse(val subjectId: Long, val name: String)

/** 거버넌스 목록 화면용 조회. 엔티티의 ID 를 이름으로 풀어 응답을 만든다 */
@Service
@Transactional(readOnly = true)
class GovernanceViewService(
    private val accessRequestService: AccessRequestService,
    private val roleRepository: RoleRepository,
    private val scopeRepository: ScopeRepository,
    private val subjectRepository: SubjectRepository,
    private val userRepository: UserRepository,
    private val policyRepository: BreakGlassPolicyRepository,
    private val assignmentService: RoleAssignmentService,
    private val groupRepository: UserGroupRepository,
) {
    fun accessRequests(requests: List<AccessRequest>): List<AccessRequestView> {
        val decisions = accessRequestService.approvalsByRequest(requests.map { it.requireId() })
        val names = subjectNames(requests.map { it.subjectId } + decisions.values.flatten().map { it.approverId })
        val roles = roles(requests.map { it.roleId })
        val scopes = scopes(requests.map { it.scopeId })
        return requests.map { r ->
            AccessRequestView(
                r.requireId(), r.requestType.name, r.subjectId, names[r.subjectId], r.roleId, roles[r.roleId]?.roleName, r.scopeId,
                scopes[r.scopeId]?.scopeCode, r.reason, r.riskLevel, r.requestedStart, r.requestedEnd, r.status.name, r.createdAt,
                decisions[r.requireId()].orEmpty().map { ApprovalView(it.approverId, names[it.approverId], it.status.name, it.comment, it.decidedAt) },
                r.closedAt,
            )
        }
    }

    fun breakGlassPolicies(policies: List<BreakGlassPolicy>): List<BreakGlassPolicyResponse> {
        val roles = roles(policies.map { it.roleId })
        val scopes = scopes(policies.map { it.scopeId })
        val groups = groupRepository.findAllById(policies.mapNotNull { it.eligibleGroupId }.toSet()).associateBy { it.requireId() }
        return policies.map { p ->
            val group = p.eligibleGroupId?.let { groups[it] }
            BreakGlassPolicyResponse(
                p.requireId(), p.policyName, p.roleId, roles[p.roleId]?.roleName, p.scopeId, scopes[p.scopeId]?.scopeCode,
                p.maxDurationMinutes, p.requireReason, p.requireApproval, p.requireMfa, p.isActive,
                p.eligibleGroupId, group?.groupCode, group?.groupName,
            )
        }
    }

    /** 켜진 그룹 (코드 순) */
    fun groupOptions(): List<GroupOption> =
        groupRepository.findAll().filter { it.isActive }.sortedBy { it.groupCode }.map { GroupOption(it.requireId(), it.groupCode, it.groupName) }

    fun breakGlassSessions(sessions: List<BreakGlassSession>): List<BreakGlassSessionResponse> {
        val policies = policyRepository.findAllById(sessions.map { it.breakGlassPolicyId }.toSet()).associateBy { it.requireId() }
        val roles = roles(policies.values.map { it.roleId })
        val names = subjectNames(sessions.map { it.subjectId } + sessions.mapNotNull { it.revokedBy })
        return sessions.map { s ->
            val policy = policies[s.breakGlassPolicyId]
            BreakGlassSessionResponse(
                s.requireId(), s.breakGlassPolicyId, policy?.policyName, s.subjectId, names[s.subjectId], policy?.roleId,
                policy?.let { roles[it.roleId]?.roleName }, s.reason, s.startTime, s.endTime, s.status.name, s.requestId,
                s.revokedBy, s.revokedBy?.let { names[it] },
            )
        }
    }

    fun delegations(delegations: List<Delegation>): List<DelegationResponse> {
        val names = subjectNames(delegations.flatMap { listOf(it.delegatorId, it.delegateId) })
        val roles = roles(delegations.map { it.roleId })
        val scopes = scopes(delegations.map { it.scopeId })
        return delegations.map { d ->
            DelegationResponse(
                d.requireId(), d.delegatorId, names[d.delegatorId], d.delegateId, names[d.delegateId], d.roleId, roles[d.roleId]?.roleName,
                d.scopeId, scopes[d.scopeId]?.scopeCode, d.startTime, d.endTime, d.reason, d.status.name, d.createdAt,
            )
        }
    }

    fun accessOptions(subjectId: Long): AccessOptionsResponse {
        val activeRoles = roleRepository.findAll().filter { it.isActive }.sortedBy { it.roleName }
        val activeScopes = scopeRepository.findAll().filter { it.isActive }.sortedBy { it.scopeCode }
        val held = assignmentService.effectiveAssignments(subjectId)
            .filter { it.sourceType != AssignmentSourceType.DELEGATION }
            .map { it.roleId to it.scopeId }.distinct()
        val roles = roles(held.map { it.first })
        val scopes = scopes(held.map { it.second })
        return AccessOptionsResponse(
            activeRoles.map { RoleOption(it.requireId(), it.roleCode, it.roleName, it.isPrivileged) },
            activeScopes.map { ScopeOption(it.requireId(), it.scopeCode, it.scopeName) },
            held.mapNotNull { (roleId, scopeId) ->
                val role = roles[roleId] ?: return@mapNotNull null
                val scope = scopes[scopeId] ?: return@mapNotNull null
                DelegatableRole(roleId, role.roleName, scopeId, scope.scopeCode)
            },
        )
    }

    /** 사번이 정확히 같은 사용 중인 사용자만 찾는다 (목록·부분 검색은 주지 않는다) */
    fun personByEmpNo(empNo: String): PersonResponse {
        val user = userRepository.findByEmpNo(empNo.trim())?.takeIf { it.status == SubjectStatus.ACTIVE }
            ?: throw NotFoundException("사용 중인 사용자(사번)", empNo)
        return PersonResponse(user.requireId(), user.name)
    }

    private fun subjectNames(ids: Collection<Long>): Map<Long, String> =
        if (ids.isEmpty()) emptyMap() else subjectRepository.findAllById(ids.toSet()).associate { it.requireId() to it.subjectName }

    private fun roles(ids: Collection<Long>): Map<Long, Role> =
        if (ids.isEmpty()) emptyMap() else roleRepository.findAllById(ids.toSet()).associateBy { it.requireId() }

    private fun scopes(ids: Collection<Long>): Map<Long, Scope> =
        if (ids.isEmpty()) emptyMap() else scopeRepository.findAllById(ids.toSet()).associateBy { it.requireId() }
}
