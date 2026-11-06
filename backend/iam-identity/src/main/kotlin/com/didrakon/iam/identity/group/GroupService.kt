package com.didrakon.iam.identity.group

import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

@Service
@Transactional
class GroupService(
    private val groupRepository: UserGroupRepository,
    private val memberRepository: GroupMemberRepository,
    private val eventPublisher: ApplicationEventPublisher,
) {
    @Transactional(readOnly = true)
    fun all(): List<UserGroup> = groupRepository.findAll().sortedBy { it.groupCode }

    @Transactional(readOnly = true)
    fun get(groupId: Long): UserGroup = groupRepository.findById(groupId).orElseThrow { NotFoundException("그룹", groupId) }

    @Transactional(readOnly = true)
    fun members(groupId: Long): List<GroupMember> = memberRepository.findByIdGroupId(groupId)

    fun create(groupCode: String, groupName: String, groupType: GroupType, ruleExpression: String?): UserGroup {
        if (groupRepository.findByGroupCode(groupCode) != null) throw BusinessRuleException("이미 있는 그룹 코드입니다: $groupCode")
        return groupRepository.save(UserGroup(groupCode, groupName, groupType, ruleExpression))
    }

    /** 유형(직접 지정·규칙)은 바꾸지 않는다. 규칙식은 규칙 그룹에만 쓴다 */
    fun update(groupId: Long, groupName: String, ruleExpression: String?): UserGroup {
        val group = get(groupId)
        if (groupName.isBlank()) throw BusinessRuleException("그룹 이름이 필요합니다")
        val before = snapshot(group)
        group.update(groupName.trim(), ruleExpression?.trim()?.ifEmpty { null }.takeIf { group.groupType == GroupType.DYNAMIC })
        eventPublisher.publishEvent(AdminChangeEvent("GROUP", groupId, "UPDATE", before, snapshot(group)))
        return group
    }

    /** 구성원이 남아 있으면 끌 수 없다 (그룹 역할 규칙으로 받은 역할이 남지 않도록 구성원부터 뺀다) */
    fun changeActive(groupId: Long, active: Boolean): UserGroup {
        val group = get(groupId)
        if (group.isActive == active) return group
        if (!active && memberRepository.findByIdGroupId(groupId).isNotEmpty()) {
            throw BusinessRuleException("구성원이 남아 있는 그룹은 끌 수 없습니다. 구성원을 먼저 빼세요")
        }
        val before = snapshot(group)
        group.changeActive(active)
        eventPublisher.publishEvent(AdminChangeEvent("GROUP", groupId, if (active) "ACTIVATE" else "DEACTIVATE", before, snapshot(group)))
        return group
    }

    private fun snapshot(g: UserGroup) = mapOf("groupName" to g.groupName, "ruleExpression" to g.ruleExpression, "isActive" to g.isActive)
}
