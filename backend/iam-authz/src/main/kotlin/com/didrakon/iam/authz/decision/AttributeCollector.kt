package com.didrakon.iam.authz.decision

import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.Attributes
import com.didrakon.iam.authz.resource.Resource
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.User
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component

/**
 * ABAC 규칙이 읽는 속성을 모은다. 규칙의 attribute_name 으로 쓸 수 있는 이름은 여기 정의된 것뿐이다.
 *
 * - SUBJECT: subjectType, userKind(사용자일 때 EMPLOYEE·EXTERNAL), status, employmentStatus, orgIds, companyOrgIds, primaryOrgId, primaryCompanyOrgId, isManager, roleCodes
 * - RESOURCE: resourceId, resourceKey, resourceType, sensitivity, clientId
 * - CONTEXT: 요청의 context + orgId(대상 조직)
 * - SESSION: 요청의 session
 * - RELATION: subject 가 이 리소스와 맺은 관계 코드 (예: OWNS) → true
 */
@Component
class AttributeCollector(
    private val subjectRepository: SubjectRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val organizationRepository: OrganizationRepository,
) {
    fun collect(
        request: AuthorizationRequest,
        resource: Resource,
        roleCodes: Collection<String>,
        relationCodes: Collection<String>,
    ): Attributes = Attributes(
        mapOf(
            AttributeSource.SUBJECT to subjectAttributes(request.subjectId, roleCodes),
            AttributeSource.RESOURCE to mapOf(
                "resourceId" to resource.id,
                "resourceKey" to resource.resourceKey,
                "resourceType" to resource.resourceType,
                "sensitivity" to resource.sensitivity,
                "clientId" to resource.clientId,
            ),
            AttributeSource.CONTEXT to request.context + ("orgId" to request.orgId),
            AttributeSource.SESSION to request.session,
            AttributeSource.RELATION to relationCodes.associateWith { true },
        ),
    )

    private fun subjectAttributes(subjectId: Long, roleCodes: Collection<String>): Map<String, Any?> {
        val subject = subjectRepository.findByIdOrNull(subjectId) ?: return emptyMap()
        val memberships = membershipRepository.findActiveBySubjectId(subjectId)
        val companyByOrg = organizationRepository.findAllById(memberships.map { it.orgId }).associate { it.requireId() to it.companyOrgId }
        val primary = memberships.firstOrNull { it.membershipType == MembershipType.PRIMARY }
        return mapOf(
            "subjectType" to subject.subjectType,
            "userKind" to (subject as? User)?.userKind,
            "status" to subject.status,
            "employmentStatus" to (subject as? User)?.employmentStatus,
            "orgIds" to memberships.map { it.orgId },
            "companyOrgIds" to memberships.mapNotNull { companyByOrg[it.orgId] }.distinct(),
            "primaryOrgId" to primary?.orgId,
            "primaryCompanyOrgId" to primary?.let { companyByOrg[it.orgId] },
            "isManager" to memberships.any { it.isManager },
            "roleCodes" to roleCodes.toList(),
        )
    }
}

