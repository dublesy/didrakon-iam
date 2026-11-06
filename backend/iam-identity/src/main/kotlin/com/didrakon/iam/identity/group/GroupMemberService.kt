package com.didrakon.iam.identity.group

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.event.GroupMembershipChange
import com.didrakon.iam.identity.event.GroupMembershipChangedEvent
import com.didrakon.iam.identity.subject.SubjectRepository
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

@Service
@Transactional
class GroupMemberService(
    private val groupRepository: UserGroupRepository,
    private val memberRepository: GroupMemberRepository,
    private val subjectRepository: SubjectRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    fun addMember(
        groupId: Long,
        subjectId: Long,
        sourceType: GroupMemberSourceType = GroupMemberSourceType.MANUAL,
    ): GroupMember {
        if (!groupRepository.existsById(groupId)) throw NotFoundException("그룹", groupId)
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        if (memberRepository.existsById(GroupMemberId(groupId, subjectId))) {
            throw BusinessRuleException("이미 그룹 구성원입니다: groupId=$groupId, subjectId=$subjectId")
        }
        val member = memberRepository.save(GroupMember(groupId, subjectId, sourceType, clock.instant()))
        eventPublisher.publishEvent(GroupMembershipChangedEvent(groupId, subjectId, GroupMembershipChange.ADDED))
        return member
    }

    /** 연결 데이터라 hard delete 한다 */
    fun removeMember(groupId: Long, subjectId: Long) {
        val id = GroupMemberId(groupId, subjectId)
        val member = memberRepository.findByIdOrNull(id) ?: throw NotFoundException("그룹 구성원", id)
        memberRepository.delete(member)
        // 구독자가 남은 구성원을 조회하므로 삭제를 먼저 반영한다
        memberRepository.flush()
        eventPublisher.publishEvent(GroupMembershipChangedEvent(groupId, subjectId, GroupMembershipChange.REMOVED))
    }
}
