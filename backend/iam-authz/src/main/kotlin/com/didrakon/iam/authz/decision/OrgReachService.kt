package com.didrakon.iam.authz.decision

import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 권한이 닿는 조직. [All] 은 조직 제한이 없다 (GLOBAL·RESOURCE 범위로 받은 권한) */
sealed interface OrgReach {
    fun contains(orgId: Long?): Boolean

    fun isEmpty(): Boolean

    data object All : OrgReach {
        override fun contains(orgId: Long?) = true

        override fun isEmpty() = false
    }

    /** 이 조직들 안에서만. 비어 있으면 어디에도 권한이 없다 */
    data class Orgs(val orgIds: Set<Long>) : OrgReach {
        override fun contains(orgId: Long?) = orgId != null && orgId in orgIds

        override fun isEmpty() = orgIds.isEmpty()
    }

    companion object {
        val NONE: OrgReach = Orgs(emptySet())

        fun union(a: OrgReach, b: OrgReach): OrgReach = when {
            a is All || b is All -> All
            else -> Orgs((a as Orgs).orgIds + (b as Orgs).orgIds)
        }

        fun intersect(a: OrgReach, b: OrgReach): OrgReach = when {
            a is All -> b
            b is All -> a
            else -> Orgs((a as Orgs).orgIds intersect (b as Orgs).orgIds)
        }
    }
}

/**
 * subject 의 (리소스, 행위) 권한이 어느 조직까지 닿는지 계산한다. 조직 단위 관리자의 목록을 거를 때 쓴다.
 *
 * PDP 의 RBAC 단계와 같은 재료(유효한 할당 × 유효한 역할 권한, 할당 scope ∩ 권한 scope)를 조직 집합으로 펼친다:
 * GLOBAL → 전체, ORGANIZATION → 그 조직(include_descendants 면 하위 전체), RESOURCE → 요청 리소스를 덮으면 전체,
 * PROJECT·DATA → 없음. 허용(ALLOW) 권한만 보며, DENY 권한·ABAC 정책은 반영하지 않는다
 * (목록을 거르는 용도이고, 호출 자체는 PDP 가 따로 판정한다).
 */
@Service
@Transactional(readOnly = true)
class OrgReachService(
    private val subjectRepository: SubjectRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val roleRepository: RoleRepository,
    private val permissionRepository: PermissionRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val scopeRepository: ScopeRepository,
    private val resourceRepository: ResourceRepository,
    private val organizationRepository: OrganizationRepository,
    private val clock: Clock,
) {
    fun reach(subjectId: Long, resourceId: Long, action: PermissionAction): OrgReach =
        reachAll(subjectId, listOf(resourceId to action)).getValue(resourceId to action)

    /** 여러 (리소스 ID, 행위) 를 한 번에. 사용 중이 아닌 subject 는 모두 [OrgReach.NONE] */
    fun reachAll(subjectId: Long, targets: Collection<Pair<Long, PermissionAction>>): Map<Pair<Long, PermissionAction>, OrgReach> {
        val now = clock.instant()
        val assignments = usableAssignments(subjectId, now)
        if (assignments.isEmpty()) return targets.associateWith { OrgReach.NONE }

        val activeResources = resourceRepository.findAllById(targets.map { it.first }.distinct()).filter { it.isActive }.map { it.requireId() }.toSet()
        val permissionsByTarget = targets.associateWith { (resourceId, action) ->
            if (resourceId !in activeResources) {
                emptySet()
            } else {
                permissionRepository.findByResourceIdAndActionAndIsActiveTrue(resourceId, action)
                    .filter { it.effect == PermissionEffect.ALLOW }.map { it.requireId() }.toSet()
            }
        }
        val permissionIds = permissionsByTarget.values.flatten().toSet()
        if (permissionIds.isEmpty()) return targets.associateWith { OrgReach.NONE }

        val rolePermissions = rolePermissionRepository.findEffective(assignments.map { it.roleId }.toSet(), permissionIds, now)
        val scopes = scopeRepository.findAllById((assignments.map { it.scopeId } + rolePermissions.map { it.scopeId }).distinct())
            .associateBy { it.requireId() }
        val subtrees = HashMap<Long, Set<Long>>()
        val resourceChains = HashMap<Long, Set<Long>>()

        fun scopeReach(scopeId: Long, resourceId: Long): OrgReach {
            val scope = scopes[scopeId]?.takeIf { it.isActive } ?: return OrgReach.NONE
            return when (scope.scopeType) {
                ScopeType.GLOBAL -> OrgReach.All
                ScopeType.ORGANIZATION -> scope.orgId?.let { orgId ->
                    OrgReach.Orgs(if (scope.includeDescendants) subtrees.getOrPut(orgId) { organizationRepository.findSubtreeIds(orgId).toSet() } else setOf(orgId))
                } ?: OrgReach.NONE
                ScopeType.RESOURCE -> if (coversResource(scope, resourceId, resourceChains)) OrgReach.All else OrgReach.NONE
                ScopeType.PROJECT, ScopeType.DATA -> OrgReach.NONE
            }
        }

        return targets.associateWith { target ->
            val ids = permissionsByTarget.getValue(target)
            assignments.flatMap { a ->
                rolePermissions.filter { it.roleId == a.roleId && it.permissionId in ids }
                    .map { rp -> OrgReach.intersect(scopeReach(a.scopeId, target.first), scopeReach(rp.scopeId, target.first)) }
            }.fold(OrgReach.NONE, OrgReach::union)
        }
    }

    /**
     * subject 가 [resourceIds] 중 어느 리소스에든 허용 권한을 가진 역할을 갖고 있거나 곧 받는가 (범위 무관).
     * 조직 단위 관리자가 다른 관리자를 바꾸지 못하게 막는 데 쓴다. 승인된 JIT·시작 전 위임처럼 앞으로 시작할 할당도 센다
     * (시작 전에 비밀번호·MFA 를 초기화해 두면 시작 시각에 그 관리 권한을 가로챌 수 있다)
     */
    fun holdsPermissionOn(subjectId: Long, resourceIds: Collection<Long>): Boolean {
        if (resourceIds.isEmpty()) return false
        val now = clock.instant()
        val roleIds = assignmentRepository.findCurrentOrUpcoming(subjectId, now).map { it.roleId }.toSet()
        if (roleIds.isEmpty()) return false
        val activeRoleIds = roleRepository.findAllById(roleIds).filter { it.isActive }.map { it.requireId() }
        if (activeRoleIds.isEmpty()) return false
        val permissionIds = permissionRepository.findByResourceIdInAndIsActiveTrue(resourceIds)
            .filter { it.effect == PermissionEffect.ALLOW }.map { it.requireId() }
        if (permissionIds.isEmpty()) return false
        return rolePermissionRepository.findEffective(activeRoleIds, permissionIds, now).isNotEmpty()
    }

    private fun usableAssignments(subjectId: Long, now: Instant): List<RoleAssignment> {
        val subject = subjectRepository.findByIdOrNull(subjectId) ?: return emptyList()
        if (subject.status != SubjectStatus.ACTIVE) return emptyList()
        val assignments = assignmentRepository.findEffective(subjectId, now)
        val activeRoleIds = roleRepository.findAllById(assignments.map { it.roleId }.distinct()).filter { it.isActive }.map { it.requireId() }.toSet()
        return assignments.filter { it.roleId in activeRoleIds }
    }

    private fun coversResource(scope: Scope, resourceId: Long, chains: MutableMap<Long, Set<Long>>): Boolean =
        scope.resourceId == resourceId ||
            (scope.includeDescendants && scope.resourceId in chains.getOrPut(resourceId) { resourceRepository.findAncestorIds(resourceId).toSet() })
}
