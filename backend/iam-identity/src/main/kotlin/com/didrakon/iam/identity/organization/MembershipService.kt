package com.didrakon.iam.identity.organization

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.event.MembershipChange
import com.didrakon.iam.identity.event.MembershipChangedEvent
import com.didrakon.iam.identity.event.MembershipUpdatedEvent
import com.didrakon.iam.identity.event.PrimaryMembershipTransferredEvent
import com.didrakon.iam.identity.subject.SubjectRepository
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

@Service
@Transactional
class MembershipService(
    private val membershipRepository: SubjectOrganizationRepository,
    private val subjectRepository: SubjectRepository,
    private val organizationRepository: OrganizationRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    fun join(
        subjectId: Long,
        orgId: Long,
        membershipType: MembershipType,
        jobTitle: String? = null,
        jobGrade: String? = null,
        isManager: Boolean = false,
    ): SubjectOrganization {
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        if (!organizationRepository.existsById(orgId)) throw NotFoundException("조직", orgId)
        if (membershipType == MembershipType.PRIMARY && membershipRepository.findActivePrimary(subjectId) != null) {
            throw BusinessRuleException("이미 활성 PRIMARY 소속이 있습니다. 소속 이동은 transferPrimary 로 처리합니다: subjectId=$subjectId")
        }
        val membership = membershipRepository.save(
            SubjectOrganization(subjectId, orgId, membershipType, clock.instant(), jobTitle, jobGrade, isManager),
        )
        eventPublisher.publishEvent(
            MembershipChangedEvent(subjectId, membership.requireId(), orgId, membershipType, MembershipChange.JOINED),
        )
        return membership
    }

    @Transactional(readOnly = true)
    fun activeMemberships(subjectId: Long): List<SubjectOrganization> = membershipRepository.findActiveBySubjectId(subjectId)

    @Transactional(readOnly = true)
    fun activeMembers(orgId: Long): List<SubjectOrganization> = membershipRepository.findActiveByOrgIdIn(listOf(orgId))

    fun leave(membershipId: Long) {
        val membership = membershipRepository.findByIdOrNull(membershipId) ?: throw NotFoundException("소속", membershipId)
        membership.end(clock.instant())
        eventPublisher.publishEvent(
            MembershipChangedEvent(
                membership.subjectId, membershipId, membership.orgId, membership.membershipType, MembershipChange.LEFT,
            ),
        )
    }

    /** 현재 소속의 직위·직급·조직장 여부를 고친다. 조직은 그대로다 (조직이 바뀌면 [transferPrimary]) */
    fun updateJob(membershipId: Long, jobTitle: String?, jobGrade: String?, isManager: Boolean): SubjectOrganization {
        val membership = membershipRepository.findByIdOrNull(membershipId) ?: throw NotFoundException("소속", membershipId)
        if (membership.validUntil != null) throw BusinessRuleException("종료된 소속은 고칠 수 없습니다: $membershipId")
        val before = jobSnapshot(membership)
        membership.updateJob(jobTitle, jobGrade, isManager)
        val after = jobSnapshot(membership)
        if (before != after) {
            eventPublisher.publishEvent(MembershipUpdatedEvent(membership.subjectId, membershipId, membership.orgId, before, after))
        }
        return membership
    }

    private fun jobSnapshot(m: SubjectOrganization) = mapOf("jobTitle" to m.jobTitle, "jobGrade" to m.jobGrade, "isManager" to m.isManager)

    /** 현재 PRIMARY 소속을 종료하고 새 조직을 PRIMARY 소속으로 만든다 (전적·전보) */
    fun transferPrimary(
        subjectId: Long,
        newOrgId: Long,
        jobTitle: String? = null,
        jobGrade: String? = null,
        isManager: Boolean = false,
    ): SubjectOrganization {
        val previous = membershipRepository.findActivePrimary(subjectId)
        previous?.let {
            it.end(clock.instant())
            // Hibernate 는 flush 시 INSERT 를 UPDATE 보다 먼저 실행하므로 종료가 늦게 반영되면 활성 PRIMARY UNIQUE 에 걸린다.
            // 지금은 join() 의 조회가 자동 flush 를 일으키지만, 그 조회에 기대지 않도록 여기서 반영한다
            membershipRepository.flush()
        }
        val membership = join(subjectId, newOrgId, MembershipType.PRIMARY, jobTitle, jobGrade, isManager)
        eventPublisher.publishEvent(PrimaryMembershipTransferredEvent(subjectId, previous?.orgId, newOrgId))
        return membership
    }
}
