package com.didrakon.iam.authz

import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.Policy
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyRuleRepository
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionRepository
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.PolicyVersionStatus
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.common.error.BusinessRuleException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import kotlin.test.assertEquals

@AuthzTest
class PolicyVersionServiceTests @Autowired constructor(
    private val versionService: PolicyVersionService,
    private val policyRepository: PolicyRepository,
    private val versionRepository: PolicyVersionRepository,
    private val ruleRepository: PolicyRuleRepository,
) {
    private val koreaOnly = RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.EQ, "\"KR\"")

    @Test
    fun `버전은 1부터 차례로 붙고 규칙이 함께 저장된다`() {
        val policyId = newPolicy()

        val v1 = versionService.createVersion(policyId, listOf(koreaOnly))
        val v2 = versionService.createVersion(policyId, emptyList(), changeReason = "조건 제거")

        assertEquals(1, v1.version)
        assertEquals(2, v2.version)
        assertEquals(PolicyVersionStatus.DRAFT, v2.status)
        assertEquals(1, ruleRepository.findByPolicyVersionIdIn(listOf(v1.requireId())).size)
    }

    @Test
    fun `새 버전을 활성화하면 이전 ACTIVE 버전은 RETIRED 가 되어 ACTIVE 는 하나만 남는다`() {
        val policyId = newPolicy()
        val v1 = versionService.createVersion(policyId, listOf(koreaOnly))
        val v2 = versionService.createVersion(policyId, listOf(koreaOnly))
        versionService.activate(v1.requireId())

        versionService.activate(v2.requireId())

        assertEquals(PolicyVersionStatus.RETIRED, v1.status)
        assertEquals(listOf(v2.requireId()), versionRepository.findByPolicyIdAndStatus(policyId, PolicyVersionStatus.ACTIVE).map { it.requireId() })
    }

    @Test
    fun `DRAFT 가 아닌 버전은 다시 활성화할 수 없다`() {
        val v1 = versionService.createVersion(newPolicy(), listOf(koreaOnly))
        versionService.activate(v1.requireId())

        assertThrows<BusinessRuleException> { versionService.activate(v1.requireId()) }
    }

    @Test
    fun `연산자에 맞지 않는 규칙이 있으면 버전을 만들지 않는다`() {
        val policyId = newPolicy()
        val invalid = RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.IN, "\"KR\"")

        assertThrows<BusinessRuleException> { versionService.createVersion(policyId, listOf(invalid)) }
        assertEquals(0, versionRepository.findMaxVersion(policyId))
    }

    private fun newPolicy(): Long =
        policyRepository.save(Policy("POLICY-${System.nanoTime()}", "정책", PolicyType.AUTHORIZATION, PolicyEffect.DENY)).requireId()
}
