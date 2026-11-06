package com.didrakon.iam.authz

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.GroupRoleService
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import kotlin.test.assertEquals

/** 조직·그룹 역할 규칙이 구성원별 ROLE_ASSIGNMENT 로 생기고 사라지는지 확인한다 */
@AuthzTest
class RoleSyncTests @Autowired constructor(
    private val organizationRoleService: OrganizationRoleService,
    private val groupRoleService: GroupRoleService,
    private val membershipService: MembershipService,
    private val organizationService: OrganizationService,
    private val groupMemberService: GroupMemberService,
    private val groupRepository: UserGroupRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val fixture: AuthzFixture,
) {
    @Test
    fun `하위 조직 포함 규칙은 하위 조직 구성원에게, 미포함 규칙은 그 조직 구성원에게만 부여된다`() {
        val company = fixture.org(OrgType.COMPANY)
        val team = fixture.org(OrgType.TEAM, company)
        val teamMember = fixture.user().also { fixture.join(it, team) }
        val companyMember = fixture.user().also { fixture.join(it, company) }
        val inherited = fixture.role().requireId()
        val companyOnly = fixture.role().requireId()

        organizationRoleService.create(company, inherited, applyToDescendants = true)
        organizationRoleService.create(company, companyOnly, applyToDescendants = false)

        assertEquals(setOf(inherited), orgRoles(teamMember))
        assertEquals(setOf(inherited, companyOnly), orgRoles(companyMember))
    }

    @Test
    fun `소속이 생기면 부여되고 끝나면 회수된다`() {
        val company = fixture.org(OrgType.COMPANY)
        val roleId = fixture.role().requireId()
        organizationRoleService.create(company, roleId, applyToDescendants = true)
        val userId = fixture.user()

        val membership = membershipService.join(userId, company, MembershipType.PRIMARY)
        assertEquals(setOf(roleId), orgRoles(userId))

        membershipService.leave(membership.requireId())
        assertEquals(emptySet(), orgRoles(userId))
    }

    @Test
    fun `겸직 소속도 조직 역할을 받고, 같은 규칙에 두 번 해당해도 할당은 하나다`() {
        val company = fixture.org(OrgType.COMPANY)
        val teamA = fixture.org(OrgType.TEAM, company)
        val teamB = fixture.org(OrgType.TEAM, company)
        val roleId = fixture.role().requireId()
        organizationRoleService.create(company, roleId, applyToDescendants = true)
        val userId = fixture.user()

        fixture.join(userId, teamA, MembershipType.PRIMARY)
        fixture.join(userId, teamB, MembershipType.SECONDARY)

        assertEquals(1, assignmentRepository.findActiveBySource(userId, AssignmentSourceType.ORGANIZATION).size)
    }

    @Test
    fun `조직을 다른 법인 아래로 옮기면 이전 상위 규칙은 회수되고 새 상위 규칙이 부여된다`() {
        val companyA = fixture.org(OrgType.COMPANY)
        val companyB = fixture.org(OrgType.COMPANY)
        val team = fixture.org(OrgType.TEAM, companyA)
        val roleA = fixture.role().requireId()
        val roleB = fixture.role().requireId()
        organizationRoleService.create(companyA, roleA, applyToDescendants = true)
        organizationRoleService.create(companyB, roleB, applyToDescendants = true)
        val userId = fixture.user().also { fixture.join(it, team) }

        organizationService.move(team, newParentOrgId = companyB)

        assertEquals(setOf(roleB), orgRoles(userId))
    }

    @Test
    fun `조직 역할 규칙을 끄면 그 규칙으로 생긴 할당이 회수된다`() {
        val company = fixture.org(OrgType.COMPANY)
        val userId = fixture.user().also { fixture.join(it, company) }
        val rule = organizationRoleService.create(company, fixture.role().requireId())

        organizationRoleService.deactivate(rule.requireId())

        assertEquals(emptySet(), orgRoles(userId))
    }

    @Test
    fun `그룹 역할은 구성원 추가·제거와 규칙 삭제를 따라간다`() {
        val group = groupRepository.save(UserGroup("G-${System.nanoTime()}", "그룹", GroupType.STATIC))
        val existing = fixture.user()
        groupMemberService.addMember(group.requireId(), existing)
        val roleId = fixture.role().requireId()

        val rule = groupRoleService.create(group.requireId(), roleId)
        assertEquals(setOf(roleId), groupRoles(existing))

        val newcomer = fixture.user()
        groupMemberService.addMember(group.requireId(), newcomer)
        assertEquals(setOf(roleId), groupRoles(newcomer))

        groupMemberService.removeMember(group.requireId(), newcomer)
        assertEquals(emptySet(), groupRoles(newcomer))

        groupRoleService.delete(rule.requireId())
        assertEquals(emptySet(), groupRoles(existing))
    }

    private fun orgRoles(subjectId: Long): Set<Long> =
        assignmentRepository.findActiveBySource(subjectId, AssignmentSourceType.ORGANIZATION).map { it.roleId }.toSet()

    private fun groupRoles(subjectId: Long): Set<Long> =
        assignmentRepository.findActiveBySource(subjectId, AssignmentSourceType.GROUP).map { it.roleId }.toSet()
}
