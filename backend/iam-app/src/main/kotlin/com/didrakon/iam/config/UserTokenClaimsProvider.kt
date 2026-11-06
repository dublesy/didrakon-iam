package com.didrakon.iam.config

import com.didrakon.iam.authn.token.UserTokenClaims
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.User
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component
import org.springframework.transaction.annotation.Transactional

/**
 * 연동 시스템이 매 요청 PDP 를 부르지 않고도 쓸 수 있는 값을 사용자 토큰에 넣는다.
 * 토큰 수명(접근 토큰 10분) 동안은 바뀐 값이 반영되지 않으므로 메뉴 노출 같은 거친 판단에만 쓰고,
 * 결재·개인정보 조회 같은 세밀한 판단은 /api/v1/authz/check 로 한다.
 *
 * - emp_no, name: 사번·이름 (사용자일 때. 외부 사용자는 사번이 없어 emp_no 를 넣지 않는다)
 * - user_kind: 사용자 구분 EMPLOYEE·EXTERNAL (사용자일 때)
 * - primary_org_id, company_org_id: 주 소속 조직과 그 법인 (문자열. SAS 는 인가 기록을 다시 읽을 때 Long 을 허용하지 않는다)
 * - roles: 지금 유효한 역할 코드 (출처 무관, 켜진 역할만)
 */
@Component
class UserTokenClaimsProvider(
    private val subjectRepository: SubjectRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val organizationRepository: OrganizationRepository,
    private val assignmentService: RoleAssignmentService,
    private val roleRepository: RoleRepository,
) : UserTokenClaims {
    @Transactional(readOnly = true)
    override fun claimsOf(subjectId: Long): Map<String, Any> {
        val claims = linkedMapOf<String, Any>()
        val subject = subjectRepository.findByIdOrNull(subjectId) ?: return claims
        claims["name"] = subject.subjectName
        (subject as? User)?.let { user ->
            claims["user_kind"] = user.userKind.name
            user.empNo?.let { claims["emp_no"] = it }
        }

        membershipRepository.findActivePrimary(subjectId)?.let { primary ->
            claims["primary_org_id"] = primary.orgId.toString()
            organizationRepository.findByIdOrNull(primary.orgId)?.companyOrgId?.let { claims["company_org_id"] = it.toString() }
        }

        val roleIds = assignmentService.effectiveAssignments(subjectId).map { it.roleId }.distinct()
        claims["roles"] = ArrayList(roleRepository.findAllById(roleIds).filter { it.isActive }.map { it.roleCode }.sorted())
        return claims
    }
}
