package com.didrakon.iam.authz.policy

import org.springframework.stereotype.Component
import java.time.Instant

/** RBAC 으로 허용된 요청에 대해 정책을 고를 때 쓰는 정보 */
data class PolicyTargetKey(
    val subjectId: Long,
    val resourceId: Long,
    /** 요청 리소스와 그 상위 리소스. 리소스 대상 정책은 하위 리소스에도 적용된다 */
    val resourceAndAncestorIds: Collection<Long>,
    /** 허용에 쓰인 권한 */
    val grantedPermissionIds: Collection<Long>,
    /** 허용에 쓰인 역할 */
    val grantedRoleIds: Collection<Long>,
)

/** 정책 하나의 평가 결과. effect 가 null 이면 이 정책은 판정을 바꾸지 않는다 */
data class PolicyOutcome(
    val policyId: Long,
    val policyCode: String,
    val effect: PolicyEffect?,
    val explanation: String,
    val relationId: Long?,
)

/**
 * 대상에 걸리는 활성 정책의 ACTIVE 버전 규칙을 평가한다.
 * - DENY·CHALLENGE·REQUIRE_APPROVAL: 조건이 맞으면 그 효과
 * - ALLOW(조건부 허용): 조건이 맞지 않으면 DENY
 * - POLICY_EXCEPTION 에 해당하면 그 정책은 건너뛴다
 * - 대상(POLICY_TARGET)이 없는 정책은 어디에도 적용되지 않는다
 */
@Component
class PolicyEvaluator(
    private val policyRepository: PolicyRepository,
    private val versionRepository: PolicyVersionRepository,
    private val ruleRepository: PolicyRuleRepository,
    private val targetRepository: PolicyTargetRepository,
    private val exceptionRepository: PolicyExceptionRepository,
    private val ruleEvaluator: RuleEvaluator,
) {
    fun evaluate(key: PolicyTargetKey, now: Instant, attributes: () -> Attributes, relationIds: () -> Map<String, Long>): List<PolicyOutcome> {
        val policyIds = targetRepository.findMatching(key.grantedPermissionIds, key.resourceAndAncestorIds, key.grantedRoleIds)
            .map { it.policyId }.distinct()
        if (policyIds.isEmpty()) return emptyList()

        val policies = policyRepository.findAllById(policyIds).filter { it.isActive }
        val activeVersions = versionRepository.findByPolicyIdInAndStatus(policyIds, PolicyVersionStatus.ACTIVE).associateBy { it.policyId }
        val rulesByVersion = ruleRepository.findByPolicyVersionIdIn(activeVersions.values.map { it.requireId() }).groupBy { it.policyVersionId }
        val exceptionsByPolicy = exceptionRepository.findByPolicyIdIn(policyIds).groupBy { it.policyId }

        return policies.mapNotNull { policy ->
            val version = activeVersions[policy.requireId()] ?: return@mapNotNull null
            val code = policy.policyCode
            if (exceptionsByPolicy[policy.requireId()].orEmpty().any { it.covers(key.subjectId, key.resourceId, now) }) {
                return@mapNotNull PolicyOutcome(policy.requireId(), code, null, "정책 $code: 예외 대상이라 건너뜀", null)
            }
            val rules = rulesByVersion[version.requireId()].orEmpty()
            val matched = ruleEvaluator.matches(rules, attributes())
            val relationId = rules.firstOrNull { it.attributeSource == AttributeSource.RELATION }
                ?.let { relationIds()[it.attributeName] }
            val effect = when (policy.effect) {
                PolicyEffect.ALLOW -> if (matched) null else PolicyEffect.DENY
                else -> if (matched) policy.effect else null
            }
            val explanation = when {
                effect == null -> "정책 $code(${policy.effect}, v${version.version}): 판정 변경 없음"
                policy.effect == PolicyEffect.ALLOW -> "정책 $code(조건부 허용, v${version.version}): 조건 불충족 → DENY"
                else -> "정책 $code(v${version.version}): 조건 일치 → $effect"
            }
            PolicyOutcome(policy.requireId(), code, effect, explanation, relationId)
        }
    }
}
