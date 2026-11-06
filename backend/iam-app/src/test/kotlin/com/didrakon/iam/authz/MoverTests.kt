package com.didrakon.iam.authz

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** ERD 문서 "전적(Mover) 처리 규칙" */
@AuthzTest
class MoverTests @Autowired constructor(
    private val membershipService: MembershipService,
    private val assignmentService: RoleAssignmentService,
    private val organizationRoleService: OrganizationRoleService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val fixture: AuthzFixture,
) {
    @Test
    fun `법인을 옮기면 이전 법인 범위 직접 권한은 회수, 그룹 전체 범위는 재검토, 겸직 법인 범위는 유지된다`() {
        val group = fixture.org(OrgType.GROUP)
        val companyA = fixture.org(OrgType.COMPANY, group)
        val companyB = fixture.org(OrgType.COMPANY, group)
        val companyC = fixture.org(OrgType.COMPANY, group)
        val teamA = fixture.org(OrgType.TEAM, companyA)
        val teamB = fixture.org(OrgType.TEAM, companyB)
        val userId = fixture.user()
        fixture.join(userId, teamA, MembershipType.PRIMARY)
        fixture.join(userId, companyC, MembershipType.SECONDARY)
        val orgRoleA = fixture.role().requireId()
        organizationRoleService.create(companyA, orgRoleA, applyToDescendants = true)

        val previousCompany = direct(userId, fixture.orgScope(companyA).requireId())
        val global = direct(userId, fixture.globalScopeId())
        val groupLevel = direct(userId, fixture.orgScope(group).requireId())
        val secondaryCompany = direct(userId, fixture.orgScope(companyC).requireId())

        membershipService.transferPrimary(userId, teamB)

        assertEquals(AssignmentStatus.REVOKED, previousCompany.status)
        assertEquals(AssignmentStatus.ACTIVE, global.status)
        assertTrue(global.reviewRequired)
        assertTrue(groupLevel.reviewRequired)
        assertEquals(AssignmentStatus.ACTIVE, secondaryCompany.status)
        assertFalse(secondaryCompany.reviewRequired)
        assertEquals(emptyList(), assignmentRepository.findActiveBySource(userId, AssignmentSourceType.ORGANIZATION).map { it.roleId })
    }

    @Test
    fun `이전 법인에 겸직이 남아 있으면 그 법인 범위 직접 권한은 유지된다`() {
        val companyA = fixture.org(OrgType.COMPANY)
        val companyB = fixture.org(OrgType.COMPANY)
        val userId = fixture.user()
        fixture.join(userId, fixture.org(OrgType.TEAM, companyA), MembershipType.PRIMARY)
        fixture.join(userId, fixture.org(OrgType.TEAM, companyA), MembershipType.SECONDARY)
        val companyAScope = direct(userId, fixture.orgScope(companyA).requireId())

        membershipService.transferPrimary(userId, fixture.org(OrgType.TEAM, companyB))

        assertEquals(AssignmentStatus.ACTIVE, companyAScope.status)
    }

    @Test
    fun `같은 법인 안의 이동은 전적이 아니므로 직접 권한을 건드리지 않는다`() {
        val company = fixture.org(OrgType.COMPANY)
        val userId = fixture.user()
        fixture.join(userId, fixture.org(OrgType.TEAM, company), MembershipType.PRIMARY)
        val companyScope = direct(userId, fixture.orgScope(company).requireId())
        val global = direct(userId, fixture.globalScopeId())

        membershipService.transferPrimary(userId, fixture.org(OrgType.TEAM, company))

        assertEquals(AssignmentStatus.ACTIVE, companyScope.status)
        assertFalse(global.reviewRequired)
    }

    private fun direct(userId: Long, scopeId: Long): RoleAssignment =
        assignmentService.assignDirect(userId, fixture.role().requireId(), scopeId)
}
