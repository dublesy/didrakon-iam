package com.didrakon.iam.config

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.authz.assignment.GroupRoleRepository
import com.didrakon.iam.authz.assignment.OrganizationRoleRepository
import com.didrakon.iam.authz.policy.PolicyExceptionRepository
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.governance.breakglass.BreakGlassPolicyRepository
import org.slf4j.LoggerFactory
import org.springframework.boot.context.event.ApplicationReadyEvent
import org.springframework.context.event.EventListener
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.stereotype.Component
import java.time.Clock

/**
 * 기동할 때, 지금 규칙으로는 만들 수 없지만 이전 버전에서 만들어졌을 수 있는 위험한 데이터를 찾아 경고 로그로 알린다.
 * 바꾸거나 지우지는 않는다 (관리자가 확인하고 끈다). 초기 구성([IamBootstrap]) 뒤에 돈다
 */
@Component
class LegacyDataCheck(
    private val authorizer: AdminAuthorizer,
    private val policyRepository: PolicyRepository,
    private val policyExceptionRepository: PolicyExceptionRepository,
    private val organizationRoleRepository: OrganizationRoleRepository,
    private val groupRoleRepository: GroupRoleRepository,
    private val breakGlassPolicyRepository: BreakGlassPolicyRepository,
    private val jdbc: JdbcTemplate,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @EventListener(ApplicationReadyEvent::class)
    fun report() {
        findings().forEach { log.warn("이전 데이터 점검: {}", it) }
    }

    /** 찾은 것마다 한 줄. 없으면 빈 목록 */
    fun findings(): List<String> {
        val now = clock.instant()
        val found = mutableListOf<String>()

        policyRepository.findAll().firstOrNull { it.policyCode == IamBootstrap.MFA_POLICY }?.let { mfa ->
            val exceptions = policyExceptionRepository.findByPolicyIdIn(listOf(mfa.requireId())).filter { it.validUntil?.isAfter(now) ?: true }
            if (exceptions.isNotEmpty()) {
                found += "관리 API MFA 정책에 예외가 있습니다 (그 대상은 비밀번호만으로 관리 API 를 씁니다): 예외 ID ${exceptions.map { it.requireId() }}"
            }
        }

        val orgRules = organizationRoleRepository.findAll().filter { it.isEffectiveAt(now) && authorizer.isConsoleRole(it.roleId) }
        if (orgRules.isNotEmpty()) found += "관리 콘솔 권한이 있는 역할을 주는 조직 역할 규칙이 있습니다: 규칙 ID ${orgRules.map { it.requireId() }}"

        val groupRules = groupRoleRepository.findAll().filter { it.isEffectiveAt(now) && authorizer.isConsoleRole(it.roleId) }
        if (groupRules.isNotEmpty()) found += "관리 콘솔 권한이 있는 역할을 주는 그룹 역할 규칙이 있습니다: 규칙 ID ${groupRules.map { it.requireId() }}"

        val ruleAssignments = jdbc.queryForList(
            "SELECT assignment_id, role_id FROM role_assignment WHERE status = 'ACTIVE' AND source_type IN ('ORGANIZATION', 'GROUP')",
        ).filter { authorizer.isConsoleRole((it["role_id"] as Number).toLong()) }.map { (it["assignment_id"] as Number).toLong() }
        if (ruleAssignments.isNotEmpty()) found += "조직·그룹 규칙으로 받은 관리 콘솔 역할 할당이 남아 있습니다: 할당 ID $ruleAssignments"

        val noApproval = breakGlassPolicyRepository.findAll().filter { !it.requireApproval && authorizer.isConsoleRole(it.roleId) }
        if (noApproval.isNotEmpty()) {
            found += "관리 콘솔 권한이 있는 역할을 승인 없이 주는 비상 접근 정책이 있습니다: 정책 ID ${noApproval.map { it.requireId() }}"
        }
        return found
    }
}
