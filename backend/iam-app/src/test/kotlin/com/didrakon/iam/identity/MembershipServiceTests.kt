package com.didrakon.iam.identity

import com.didrakon.iam.TestcontainersConfiguration
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import jakarta.persistence.EntityManager
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
@Transactional
class MembershipServiceTests @Autowired constructor(
    private val membershipService: MembershipService,
    private val organizationService: OrganizationService,
    private val userRepository: UserRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val entityManager: EntityManager,
) {
    @Test
    fun `활성 PRIMARY 소속이 있으면 PRIMARY 소속을 추가할 수 없다`() {
        val userId = newUser()
        membershipService.join(userId, newCompany("CO-A"), MembershipType.PRIMARY)

        assertThrows<BusinessRuleException> {
            membershipService.join(userId, newCompany("CO-B"), MembershipType.PRIMARY)
        }
    }

    @Test
    fun `겸직 소속은 PRIMARY 소속과 함께 둘 수 있다`() {
        val userId = newUser()
        membershipService.join(userId, newCompany("CO-A"), MembershipType.PRIMARY)

        membershipService.join(userId, newCompany("CO-B"), MembershipType.SECONDARY)

        entityManager.flush()
        assertEquals(2, membershipRepository.findActiveBySubjectId(userId).size)
    }

    @Test
    fun `PRIMARY 소속을 옮기면 이전 소속은 종료되고 새 소속이 활성 PRIMARY 가 된다`() {
        val userId = newUser()
        val companyA = newCompany("CO-A")
        val companyB = newCompany("CO-B")
        val before = membershipService.join(userId, companyA, MembershipType.PRIMARY)

        membershipService.transferPrimary(userId, companyB, jobTitle = "팀장", jobGrade = "G3", isManager = true)

        entityManager.flush()
        entityManager.clear()
        val active = membershipRepository.findActivePrimary(userId)
        assertEquals(companyB, active?.orgId)
        assertEquals("팀장", active?.jobTitle)
        assertNotNull(membershipRepository.findById(before.requireId()).orElseThrow().validUntil)
    }

    @Test
    fun `소속을 종료하면 활성 소속에서 빠진다`() {
        val userId = newUser()
        val membership = membershipService.join(userId, newCompany("CO-A"), MembershipType.PRIMARY)

        membershipService.leave(membership.requireId())

        entityManager.flush()
        assertEquals(0, membershipRepository.findActiveBySubjectId(userId).size)
    }

    @Test
    fun `존재하지 않는 subject 나 조직으로는 소속을 만들 수 없다`() {
        val companyId = newCompany("CO-A")

        assertThrows<NotFoundException> { membershipService.join(-1, companyId, MembershipType.PRIMARY) }
        assertThrows<NotFoundException> { membershipService.join(newUser(), -1, MembershipType.PRIMARY) }
    }

    private fun newUser(): Long =
        userRepository.save(User(empNo = "E-${System.nanoTime()}", name = "홍길동")).requireId()

    private fun newCompany(code: String): Long =
        organizationService.create(code, code, OrgType.COMPANY, parentOrgId = null).requireId()
}
