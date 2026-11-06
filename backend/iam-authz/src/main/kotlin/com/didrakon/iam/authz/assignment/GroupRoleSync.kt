package com.didrakon.iam.authz.assignment

import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.event.GroupMembershipChangedEvent
import com.didrakon.iam.identity.group.GroupMemberRepository
import com.didrakon.iam.identity.group.UserGroupRepository
import org.springframework.context.event.EventListener
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** GROUP_ROLE 규칙을 구성원별 ROLE_ASSIGNMENT(source_type=GROUP, source_id=group_role_id) 로 맞춘다. 방식은 [OrganizationRoleSync] 와 같다 */
@Component
class GroupRoleSync(
    private val groupRoleRepository: GroupRoleRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val memberRepository: GroupMemberRepository,
    private val assignmentService: RoleAssignmentService,
    private val clock: Clock,
) {
    @EventListener
    fun onGroupMembershipChanged(event: GroupMembershipChangedEvent) = reconcile(event.subjectId)

    fun reconcileMembersOf(groupId: Long) {
        memberRepository.findByIdGroupId(groupId).forEach { reconcile(it.id.subjectId) }
    }

    fun reconcile(subjectId: Long) {
        val desired = desiredRules(subjectId, clock.instant())
        val actual = assignmentRepository.findActiveBySource(subjectId, AssignmentSourceType.GROUP)

        actual.filter { it.sourceId !in desired.keys }
            .forEach { assignmentService.revokeAssignment(it, null, "그룹 역할 규칙에 더 이상 해당하지 않음") }

        val granted = actual.mapNotNull { it.sourceId }.toSet()
        desired.filterKeys { it !in granted }.values.forEach { rule ->
            assignmentService.grant(
                subjectId, rule.roleId, rule.scopeId, AssignmentSourceType.GROUP, rule.requireId(),
                rule.validUntil, null, "그룹 역할 규칙",
            )
        }
    }

    private fun desiredRules(subjectId: Long, now: Instant): Map<Long, GroupRole> {
        val groupIds = memberRepository.findByIdSubjectId(subjectId)
            .filter { !it.validFrom.isAfter(now) && (it.validUntil?.isAfter(now) ?: true) }
            .map { it.id.groupId }
        return groupRoleRepository.findByGroupIdIn(groupIds).filter { it.isEffectiveAt(now) }.associateBy { it.requireId() }
    }
}

@Service
@Transactional
class GroupRoleService(
    private val groupRoleRepository: GroupRoleRepository,
    private val groupRepository: UserGroupRepository,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val sync: GroupRoleSync,
    private val clock: Clock,
) {
    /** 규칙을 만들고 현재 구성원에게 바로 부여한다. scope 미지정은 GLOBAL */
    fun create(groupId: Long, roleId: Long, scopeId: Long? = null): GroupRole {
        if (!groupRepository.existsById(groupId)) throw NotFoundException("그룹", groupId)
        if (!roleRepository.existsById(roleId)) throw NotFoundException("역할", roleId)
        val rule = groupRoleRepository.save(
            GroupRole(groupId, roleId, scopeId ?: assignmentService.globalScopeId(), clock.instant()),
        )
        sync.reconcileMembersOf(groupId)
        return rule
    }

    @Transactional(readOnly = true)
    fun rules(groupId: Long): List<GroupRole> = groupRoleRepository.findByGroupIdIn(listOf(groupId))

    /** 연결 데이터라 hard delete 하고, 이 규칙으로 생긴 할당은 회수된다 */
    fun delete(groupRoleId: Long) {
        val rule = groupRoleRepository.findByIdOrNull(groupRoleId) ?: throw NotFoundException("그룹 역할 규칙", groupRoleId)
        groupRoleRepository.delete(rule)
        groupRoleRepository.flush()
        sync.reconcileMembersOf(rule.groupId)
    }
}
