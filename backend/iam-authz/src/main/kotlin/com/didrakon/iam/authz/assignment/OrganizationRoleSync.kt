package com.didrakon.iam.authz.assignment

import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.event.MembershipChangedEvent
import com.didrakon.iam.identity.event.OrganizationMovedEvent
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import org.springframework.context.event.EventListener
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/**
 * ORGANIZATION_ROLE 규칙을 구성원별 ROLE_ASSIGNMENT(source_type=ORGANIZATION, source_id=org_role_id) 로 맞춘다.
 * subject 단위로 "있어야 할 할당"과 "있는 할당"을 비교해 모자란 것은 부여, 남는 것은 회수한다 (여러 번 불러도 결과가 같다).
 */
@Component
class OrganizationRoleSync(
    private val organizationRoleRepository: OrganizationRoleRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val organizationRepository: OrganizationRepository,
    private val assignmentService: RoleAssignmentService,
    private val clock: Clock,
) {
    @EventListener
    fun onMembershipChanged(event: MembershipChangedEvent) = reconcile(event.subjectId)

    /** 상위 조직이 바뀌면 상속받던 규칙이 달라지므로 하위 조직 구성원 전체를 다시 맞춘다 */
    @EventListener
    fun onOrganizationMoved(event: OrganizationMovedEvent) = reconcileMembersOf(event.subtreeOrgIds)

    fun reconcileMembersOf(orgIds: Collection<Long>) {
        membershipRepository.findActiveByOrgIdIn(orgIds).map { it.subjectId }.distinct().forEach(::reconcile)
    }

    fun reconcile(subjectId: Long) {
        val desired = desiredRules(subjectId, clock.instant())
        val actual = assignmentRepository.findActiveBySource(subjectId, AssignmentSourceType.ORGANIZATION)

        actual.filter { it.sourceId !in desired.keys }
            .forEach { assignmentService.revokeAssignment(it, null, "조직 역할 규칙에 더 이상 해당하지 않음") }

        val granted = actual.mapNotNull { it.sourceId }.toSet()
        desired.filterKeys { it !in granted }.values.forEach { rule ->
            assignmentService.grant(
                subjectId, rule.roleId, rule.scopeId, AssignmentSourceType.ORGANIZATION, rule.requireId(),
                rule.validUntil, null, "조직 역할 규칙",
            )
        }
    }

    /** 소속 조직의 규칙은 모두, 상위 조직의 규칙은 apply_to_descendants 인 것만 적용된다. 겸직·임시 소속도 포함 */
    private fun desiredRules(subjectId: Long, now: Instant): Map<Long, OrganizationRole> {
        val memberOrgIds = membershipRepository.findActiveBySubjectId(subjectId).map { it.orgId }.toSet()
        return memberOrgIds.flatMap { orgId ->
            val chain = organizationRepository.findAncestorIds(orgId)
            organizationRoleRepository.findByOrgIdInAndIsActiveTrue(chain)
                .filter { it.isEffectiveAt(now) && (it.orgId == orgId || it.applyToDescendants) }
        }.associateBy { it.requireId() }
    }
}

@Service
@Transactional
class OrganizationRoleService(
    private val organizationRoleRepository: OrganizationRoleRepository,
    private val organizationRepository: OrganizationRepository,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val sync: OrganizationRoleSync,
    private val clock: Clock,
) {
    /** 규칙을 만들고 해당 조직(apply_to_descendants 면 하위 조직 포함) 구성원에게 바로 부여한다. scope 미지정은 GLOBAL */
    fun create(orgId: Long, roleId: Long, scopeId: Long? = null, applyToDescendants: Boolean = false): OrganizationRole {
        if (!organizationRepository.existsById(orgId)) throw NotFoundException("조직", orgId)
        if (!roleRepository.existsById(roleId)) throw NotFoundException("역할", roleId)
        val rule = organizationRoleRepository.save(
            OrganizationRole(orgId, roleId, scopeId ?: assignmentService.globalScopeId(), applyToDescendants, clock.instant()),
        )
        sync.reconcileMembersOf(affectedOrgIds(rule))
        return rule
    }

    @Transactional(readOnly = true)
    fun rules(orgId: Long): List<OrganizationRole> = organizationRoleRepository.findByOrgId(orgId)

    /** 규칙을 끄면 이 규칙으로 생긴 할당이 회수된다 */
    fun deactivate(orgRoleId: Long) {
        val rule = organizationRoleRepository.findByIdOrNull(orgRoleId) ?: throw NotFoundException("조직 역할 규칙", orgRoleId)
        rule.deactivate()
        sync.reconcileMembersOf(affectedOrgIds(rule))
    }

    private fun affectedOrgIds(rule: OrganizationRole): List<Long> =
        if (rule.applyToDescendants) organizationRepository.findSubtreeIds(rule.orgId) else listOf(rule.orgId)
}
