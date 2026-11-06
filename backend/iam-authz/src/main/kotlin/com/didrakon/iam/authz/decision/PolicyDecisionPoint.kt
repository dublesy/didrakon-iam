package com.didrakon.iam.authz.decision

import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyEvaluator
import com.didrakon.iam.authz.policy.PolicyTargetKey
import com.didrakon.iam.authz.resource.RelationTypeRepository
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.resource.SubjectRelationRepository
import com.didrakon.iam.authz.role.Permission
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.RolePermission
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.risk.RiskContext
import com.didrakon.iam.risk.RiskEngine
import com.didrakon.iam.risk.RiskType
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/**
 * 권한 판정 엔진 (PDP). 판정 순서:
 * 0. 주체: 사용 중(ACTIVE)이 아니면 거부한다. 사용 안 함·잠김·퇴직 사용자는 남은 역할·토큰과 관계없이 막힌다.
 * 1. RBAC: 유효한 ROLE_ASSIGNMENT × ROLE_PERMISSION 중 할당 scope 와 권한 scope 가 모두 요청을 덮는 것만 쓴다.
 *    하나도 없으면 DENY, DENY 권한이 하나라도 있으면 DENY (deny-overrides).
 * 2. 위험: RBAC 이 허용하면 DATA_ACCESS 위험을 평가해 CONTEXT.riskScore 로 넣는다 (호출 측 값은 덮어쓴다).
 *    위험 점수만으로 막지는 않는다. 막으려면 riskScore 를 보는 ABAC 정책을 둔다.
 * 3. ABAC: RBAC 이 허용했을 때만 정책을 평가하고, 가장 강한 결과(DENY > REQUIRE_APPROVAL > CHALLENGE > ALLOW)를 택한다.
 * 4. 모든 판정은 AUTHORIZATION_LOG 에 남긴다 (위험 점수 포함).
 */
@Service
class PolicyDecisionPoint(
    private val subjectRepository: SubjectRepository,
    private val resourceRepository: ResourceRepository,
    private val permissionRepository: PermissionRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val roleRepository: RoleRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val scopeRepository: ScopeRepository,
    private val organizationRepository: OrganizationRepository,
    private val subjectRelationRepository: SubjectRelationRepository,
    private val relationTypeRepository: RelationTypeRepository,
    private val policyEvaluator: PolicyEvaluator,
    private val attributeCollector: AttributeCollector,
    private val logWriter: AuthorizationLogWriter,
    private val riskEngine: RiskEngine,
    private val clock: Clock,
) {
    @Transactional
    fun decide(request: AuthorizationRequest): AuthorizationResult {
        val startedAt = System.nanoTime()
        val now = clock.instant()
        val result = evaluate(request, now)
        logWriter.write(request, result, now, ((System.nanoTime() - startedAt) / 1_000_000).toInt())
        return result
    }

    private fun evaluate(request: AuthorizationRequest, now: Instant): AuthorizationResult {
        val subject = subjectRepository.findByIdOrNull(request.subjectId) ?: return deny("주체가 없습니다: ${request.subjectId}")
        if (subject.status != SubjectStatus.ACTIVE) return deny("사용 중이 아닌 사용자입니다: ${subject.status}")
        val resource = resourceRepository.findByIdOrNull(request.resourceId) ?: return deny("리소스가 없습니다: ${request.resourceId}")
        if (!resource.isActive) return deny("비활성 리소스입니다: ${resource.resourceKey}")
        val resourceId = resource.requireId()

        val permissions = permissionRepository.findByResourceIdAndActionAndIsActiveTrue(resourceId, request.action)
            .associateBy { it.requireId() }
        if (permissions.isEmpty()) return deny("${resource.resourceKey} 에 ${request.action} 권한이 정의되어 있지 않습니다")

        val assignments = assignmentRepository.findEffective(request.subjectId, now)
        val roles = roleRepository.findAllById(assignments.map { it.roleId }.distinct()).filter { it.isActive }.associateBy { it.requireId() }
        val usableAssignments = assignments.filter { it.roleId in roles }
        if (usableAssignments.isEmpty()) return deny("유효한 역할 할당이 없습니다")

        val rolePermissions = rolePermissionRepository.findEffective(roles.keys, permissions.keys, now)
        val scopes = scopeRepository.findAllById((usableAssignments.map { it.scopeId } + rolePermissions.map { it.scopeId }).distinct())
            .associateBy { it.requireId() }
        val resourceChain = resourceRepository.findAncestorIds(resourceId).toSet()
        val orgChain = request.orgId?.let { organizationRepository.findAncestorIds(it).toSet() }.orEmpty()
        val covers = { scopeId: Long -> scopes[scopeId]?.let { covers(it, request, resourceChain, orgChain) } ?: false }

        val grants = usableAssignments.filter { covers(it.scopeId) }.flatMap { assignment ->
            rolePermissions.filter { it.roleId == assignment.roleId && covers(it.scopeId) }
                .map { Grant(assignment, it, permissions.getValue(it.permissionId), roles.getValue(assignment.roleId).roleCode, scopes.getValue(assignment.scopeId)) }
        }
        if (grants.isEmpty()) return deny("역할은 있으나 이 리소스·행위·범위에 맞는 권한이 없습니다")

        grants.firstOrNull { it.permission.effect == PermissionEffect.DENY }?.let { denied ->
            return result(Decision.DENY, "권한 ${denied.permission.permissionCode} 이 DENY 입니다 (deny-overrides)", listOf(denied.describe()), denied)
        }
        val allowed = grants.first()

        val risk = riskEngine.assess(
            RiskContext(
                subjectId = request.subjectId,
                type = RiskType.DATA_ACCESS,
                ipAddress = request.context["ip"] as? String,
                accessCountSince = { since -> logWriter.countSince(request.subjectId, since) },
            ),
        )
        val scoredRequest = request.copy(context = request.context + ("riskScore" to risk.score))

        // ABAC 은 RBAC 이 허용한 요청에만 적용한다
        val relations by lazy { subjectRelationRepository.findEffectiveToResource(request.subjectId, resourceId, now) }
        val relationCodes by lazy {
            relationTypeRepository.findAllById(relations.map { it.relationTypeId }.distinct()).associate { it.requireId() to it.relationCode }
        }
        val attributes by lazy {
            attributeCollector.collect(scoredRequest, resource, roles.values.map { it.roleCode }, relationCodes.values)
        }
        val outcomes = policyEvaluator.evaluate(
            PolicyTargetKey(
                subjectId = request.subjectId,
                resourceId = resourceId,
                resourceAndAncestorIds = resourceChain,
                grantedPermissionIds = grants.map { it.permission.requireId() }.distinct(),
                grantedRoleIds = grants.map { it.assignment.roleId }.distinct(),
            ),
            now,
            { attributes },
            { relations.mapNotNull { r -> relationCodes[r.relationTypeId]?.let { it to r.requireId() } }.toMap() },
        )

        val explanation = grants.map { it.describe() } + outcomes.map { it.explanation }
        val strongest = outcomes.mapNotNull { o -> o.effect?.let { o to it.toDecision() } }.maxByOrNull { it.second.ordinal }
            ?: return result(Decision.ALLOW, "역할 ${allowed.roleCode} 의 권한 ${allowed.permission.permissionCode} 로 허용", explanation, allowed)
                .copy(riskScore = risk.score)

        val (policy, decision) = strongest
        return result(decision, policy.explanation, explanation, allowed).copy(
            matchedPolicyId = policy.policyId,
            matchedRelationId = policy.relationId,
            riskScore = risk.score,
        )
    }

    /** 요청이 scope 안에 있는가. PROJECT·DATA scope 는 RBAC 에서 해석하지 않으므로 매칭되지 않는다 */
    private fun covers(scope: Scope, request: AuthorizationRequest, resourceChain: Set<Long>, orgChain: Set<Long>): Boolean {
        if (!scope.isActive) return false
        return when (scope.scopeType) {
            ScopeType.GLOBAL -> true
            ScopeType.ORGANIZATION ->
                request.orgId != null && (scope.orgId == request.orgId || (scope.includeDescendants && scope.orgId in orgChain))
            ScopeType.RESOURCE ->
                scope.resourceId == request.resourceId || (scope.includeDescendants && scope.resourceId in resourceChain)
            ScopeType.PROJECT, ScopeType.DATA -> false
        }
    }

    private fun deny(reason: String) = AuthorizationResult(Decision.DENY, reason, listOf(reason))

    private fun result(decision: Decision, reason: String, explanation: List<String>, grant: Grant) = AuthorizationResult(
        decision = decision,
        reason = reason,
        explanation = explanation,
        matchedAssignmentId = grant.assignment.requireId(),
        matchedRoleId = grant.assignment.roleId,
        matchedPermissionId = grant.permission.requireId(),
        matchedScopeId = grant.assignment.scopeId,
    )

    private fun PolicyEffect.toDecision(): Decision = when (this) {
        PolicyEffect.ALLOW -> Decision.ALLOW
        PolicyEffect.DENY -> Decision.DENY
        PolicyEffect.CHALLENGE -> Decision.CHALLENGE
        PolicyEffect.REQUIRE_APPROVAL -> Decision.REQUIRE_APPROVAL
    }

    /** 판정에 쓰인 할당 1건 × 역할 권한 1건 */
    private class Grant(
        val assignment: RoleAssignment,
        val rolePermission: RolePermission,
        val permission: Permission,
        val roleCode: String,
        val assignmentScope: Scope,
    ) {
        fun describe(): String =
            "역할 $roleCode(할당 ${assignment.id}, ${assignment.sourceType}, scope ${assignmentScope.scopeCode})" +
                " → 권한 ${permission.permissionCode} ${permission.effect}"
    }
}
