package com.didrakon.iam.authz.assignment

import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.identity.event.PrimaryMembershipTransferredEvent
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import org.springframework.context.event.EventListener
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component

/**
 * 전적(PRIMARY 소속의 법인 변경) 시 직접 부여 권한을 정리한다. ERD 문서 "전적(Mover) 처리 규칙".
 * 조직 역할(source_type=ORGANIZATION)은 소속 변경 이벤트로 [OrganizationRoleSync] 가 이미 다시 맞춘다.
 *
 * | 직접 할당의 scope            | 처리                                   |
 * | 이전 법인 소속 조직          | 회수 (그 법인에 겸직·임시 소속이 남아 있으면 유지) |
 * | 법인에 묶이지 않음(그룹 전체) | 유지, review_required = true            |
 * | 그 밖의 법인                 | 영향 없음                               |
 */
@Component
class MoverHandler(
    private val organizationRepository: OrganizationRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val scopeRepository: ScopeRepository,
    private val assignmentService: RoleAssignmentService,
) {
    @EventListener
    fun onPrimaryMembershipTransferred(event: PrimaryMembershipTransferredEvent) {
        val fromCompany = event.fromOrgId?.let(::companyOf) ?: return
        // 같은 법인 안의 이동(전보)은 전적이 아니다
        if (fromCompany == companyOf(event.toOrgId)) return

        val otherMembershipCompanies = membershipRepository.findActiveBySubjectId(event.subjectId)
            .filter { it.membershipType != MembershipType.PRIMARY }
            .mapNotNull { companyOf(it.orgId) }
            .toSet()
        val directs = assignmentRepository.findActiveBySource(event.subjectId, AssignmentSourceType.DIRECT)
        val scopeOrgIds = scopeRepository.findAllById(directs.map { it.scopeId }).associate { it.requireId() to it.orgId }

        directs.forEach { assignment ->
            val scopeCompany = scopeOrgIds[assignment.scopeId]?.let(::companyOf)
            when {
                scopeCompany == null ->
                    assignmentService.requireReview(assignment, "전적: 그룹 전체 범위 권한 재검토 필요")
                scopeCompany == fromCompany && fromCompany !in otherMembershipCompanies ->
                    assignmentService.revokeAssignment(assignment, null, "전적: 이전 법인 범위 권한 자동 회수")
            }
        }
    }

    private fun companyOf(orgId: Long): Long? = organizationRepository.findByIdOrNull(orgId)?.companyOrgId
}
