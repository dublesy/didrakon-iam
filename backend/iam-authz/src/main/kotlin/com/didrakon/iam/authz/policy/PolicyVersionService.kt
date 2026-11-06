package com.didrakon.iam.authz.policy

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional

/** 규칙 한 줄의 입력값 */
data class RuleSpec(
    val ruleGroup: Int,
    val attributeSource: AttributeSource,
    val attributeName: String,
    val operator: RuleOperator,
    val attributeValue: String?,
    val ruleOrder: Int = 0,
)

/** 정책 규칙은 버전 단위로 바꾼다. 새 버전은 DRAFT 로 만들고, 활성화하면 기존 ACTIVE 는 RETIRED 가 된다 */
@Service
@Transactional
class PolicyVersionService(
    private val policyRepository: PolicyRepository,
    private val versionRepository: PolicyVersionRepository,
    private val ruleRepository: PolicyRuleRepository,
    private val ruleEvaluator: RuleEvaluator,
    private val eventPublisher: ApplicationEventPublisher,
) {
    fun createVersion(policyId: Long, rules: List<RuleSpec>, changeReason: String? = null, createdBy: Long? = null): PolicyVersion {
        // 버전 번호 채번을 직렬화한다
        policyRepository.findForUpdate(policyId) ?: throw NotFoundException("정책", policyId)
        rules.forEach { ruleEvaluator.validate(it.operator, it.attributeValue) }

        val version = versionRepository.save(
            PolicyVersion(policyId, versionRepository.findMaxVersion(policyId) + 1, changeReason, createdBy),
        )
        ruleRepository.saveAll(
            rules.map {
                PolicyRule(version.requireId(), it.ruleGroup, it.attributeSource, it.attributeName, it.operator, it.attributeValue, it.ruleOrder)
            },
        )
        return version
    }

    /** 정책 행을 잠근 채 바꿔 동시에 활성화해도 ACTIVE 가 1개만 남는다 */
    fun activate(policyVersionId: Long) {
        val version = versionRepository.findByIdOrNull(policyVersionId) ?: throw NotFoundException("정책 버전", policyVersionId)
        policyRepository.findForUpdate(version.policyId) ?: throw NotFoundException("정책", version.policyId)
        if (version.status != PolicyVersionStatus.DRAFT) {
            throw BusinessRuleException("DRAFT 버전만 활성화할 수 있습니다: $policyVersionId (${version.status})")
        }
        val previous = versionRepository.findByPolicyIdAndStatus(version.policyId, PolicyVersionStatus.ACTIVE)
        previous.forEach { it.retire() }
        version.activate()
        eventPublisher.publishEvent(
            PolicyVersionActivatedEvent(
                policyId = version.policyId,
                previousVersionId = previous.firstOrNull()?.requireId(),
                activatedVersionId = version.requireId(),
                versionCreatedBy = version.createdBy,
                changeReason = version.changeReason,
            ),
        )
    }
}

/** 정책의 ACTIVE 버전이 바뀌었다. audit 모듈이 POLICY_CHANGE_HISTORY 로 남긴다. 처음 활성화면 previousVersionId 는 null */
data class PolicyVersionActivatedEvent(
    val policyId: Long,
    val previousVersionId: Long?,
    val activatedVersionId: Long,
    /** 새 버전 작성자. 활성화한 사람은 요청 컨텍스트에 있다 */
    val versionCreatedBy: Long?,
    val changeReason: String?,
)
