package com.didrakon.iam.identity

import com.didrakon.iam.TestcontainersConfiguration
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.Organization
import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.identity.organization.OrganizationService
import jakarta.persistence.EntityManager
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional
import kotlin.test.assertEquals
import kotlin.test.assertNull

@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
@Transactional
class OrganizationServiceTests @Autowired constructor(
    private val organizationService: OrganizationService,
    private val organizationRepository: OrganizationRepository,
    private val entityManager: EntityManager,
) {
    @Test
    fun `법인은 자기 자신을, 하위 조직은 가장 가까운 상위 법인을 소속 법인으로 가진다`() {
        val group = create("GRP", OrgType.GROUP, parent = null)
        val company = create("CO-A", OrgType.COMPANY, parent = group)
        val team = create("TEAM-1", OrgType.TEAM, parent = company)

        val saved = reload(group, company, team)

        assertNull(saved[0].companyOrgId)
        assertEquals(1, saved[0].orgLevel)
        assertEquals(company.requireId(), saved[1].companyOrgId)
        assertEquals(2, saved[1].orgLevel)
        assertEquals(company.requireId(), saved[2].companyOrgId)
        assertEquals(3, saved[2].orgLevel)
    }

    @Test
    fun `조직을 이동하면 하위 조직 전체의 상위·레벨·소속 법인이 갱신된다`() {
        val group = create("GRP", OrgType.GROUP, parent = null)
        val companyA = create("CO-A", OrgType.COMPANY, parent = group)
        val companyB = create("CO-B", OrgType.COMPANY, parent = group)
        val center = create("CENTER-1", OrgType.CENTER, parent = companyB)
        val division = create("DIV-1", OrgType.DIVISION, parent = companyA)
        val team = create("TEAM-1", OrgType.TEAM, parent = division)

        organizationService.move(division.requireId(), newParentOrgId = center.requireId())

        val (movedDivision, movedTeam) = reload(division, team)
        assertEquals(center.requireId(), movedDivision.parentOrgId)
        assertEquals(4, movedDivision.orgLevel)
        assertEquals(companyB.requireId(), movedDivision.companyOrgId)
        assertEquals(5, movedTeam.orgLevel)
        assertEquals(companyB.requireId(), movedTeam.companyOrgId)
    }

    @Test
    fun `자기 하위 조직 아래로는 이동할 수 없다`() {
        val company = create("CO-A", OrgType.COMPANY, parent = null)
        val team = create("TEAM-1", OrgType.TEAM, parent = company)

        assertThrows<BusinessRuleException> {
            organizationService.move(company.requireId(), newParentOrgId = team.requireId())
        }
        assertThrows<BusinessRuleException> {
            organizationService.move(company.requireId(), newParentOrgId = company.requireId())
        }
    }

    private fun create(code: String, type: OrgType, parent: Organization?): Organization =
        organizationService.create(code, "$code 이름", type, parent?.requireId())

    /** 1차 캐시가 아닌 DB 에 반영된 값을 읽는다 */
    private fun reload(vararg orgs: Organization): List<Organization> {
        entityManager.flush()
        entityManager.clear()
        return orgs.map { organizationRepository.findById(it.requireId()).orElseThrow() }
    }
}
