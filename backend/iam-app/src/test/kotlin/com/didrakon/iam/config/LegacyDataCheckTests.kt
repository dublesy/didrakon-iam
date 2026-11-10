package com.didrakon.iam.config

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.OrganizationRole
import com.didrakon.iam.authz.assignment.OrganizationRoleRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import java.time.Instant
import kotlin.test.assertTrue

/** 기동 시 이전 데이터 점검. 테스트마다 롤백된다 */
@AuthzTest
class LegacyDataCheckTests @Autowired constructor(
    private val check: LegacyDataCheck,
    private val organizationRoleRepository: OrganizationRoleRepository,
    private val roleRepository: RoleRepository,
    private val fixture: AuthzFixture,
) {
    @Test
    fun `지금 규칙으로 만들 수 없는 관리 콘솔 역할 조직 규칙을 찾아 알린다`() {
        val before = check.findings().none { it.contains("조직 역할 규칙") }
        val auditor = roleRepository.findByRoleCode(IamBootstrap.AUDITOR_ROLE)?.requireId() ?: throw AssertionError()
        // API 로는 만들 수 없는 규칙이라 저장소에 직접 넣는다 (이전 버전에서 만든 데이터)
        val rule = organizationRoleRepository.save(OrganizationRole(fixture.org(OrgType.TEAM), auditor, fixture.globalScopeId(), false, Instant.now()))

        val findings = check.findings()

        assertTrue(before, "깨끗한 데이터에서는 알리지 않는다")
        assertTrue(findings.any { it.contains("조직 역할 규칙") && it.contains(rule.requireId().toString()) }, findings.toString())
    }
}
