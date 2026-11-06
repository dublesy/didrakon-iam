package com.didrakon.iam.authz.policy

import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 정책 대상 하나. 셋 중 정확히 하나만 채운다 */
data class PolicyTargetSpec(val permissionId: Long? = null, val resourceId: Long? = null, val roleId: Long? = null)

data class PolicyVersionView(val version: PolicyVersion, val rules: List<PolicyRule>)

data class PolicyDetail(
    val policy: Policy,
    val targets: List<PolicyTarget>,
    /** 최신 버전부터 */
    val versions: List<PolicyVersionView>,
    val exceptions: List<PolicyException>,
)

/** 정책 정의와 예외. 규칙은 [PolicyVersionService] 가 버전 단위로 다룬다 */
@Service
@Transactional
class PolicyService(
    private val policyRepository: PolicyRepository,
    private val targetRepository: PolicyTargetRepository,
    private val exceptionRepository: PolicyExceptionRepository,
    private val versionRepository: PolicyVersionRepository,
    private val ruleRepository: PolicyRuleRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    @Transactional(readOnly = true)
    fun policies(): List<Policy> = policyRepository.findAll().sortedBy { it.policyCode }

    @Transactional(readOnly = true)
    fun detail(policyId: Long): PolicyDetail {
        val policy = policyRepository.findByIdOrNull(policyId) ?: throw NotFoundException("정책", policyId)
        val versions = versionRepository.findByPolicyIdOrderByVersionDesc(policyId)
        val rules = ruleRepository.findByPolicyVersionIdIn(versions.map { it.requireId() }).groupBy { it.policyVersionId }
        return PolicyDetail(
            policy,
            targetRepository.findByPolicyId(policyId),
            versions.map { v -> PolicyVersionView(v, rules[v.requireId()].orEmpty().sortedWith(compareBy({ it.ruleGroup }, { it.ruleOrder }))) },
            exceptionRepository.findByPolicyIdIn(listOf(policyId)),
        )
    }

    /** 대상이 없는 정책은 어디에도 적용되지 않으므로 하나 이상 받는다 */
    fun create(
        policyCode: String,
        policyName: String,
        policyType: PolicyType,
        effect: PolicyEffect,
        targets: List<PolicyTargetSpec>,
        priority: Int = 0,
    ): Policy {
        if (targets.isEmpty()) throw BusinessRuleException("정책 대상이 하나 이상 필요합니다")
        val policy = policyRepository.save(Policy(policyCode, policyName, policyType, effect, priority))
        targets.forEach { targetRepository.save(target(policy.requireId(), it)) }
        return policy
    }

    /** 유형·효과는 바꾸지 않는다 (판정 의미가 버전 이력 밖에서 바뀌지 않도록). 규칙은 새 버전으로 바꾼다 */
    fun update(policyId: Long, policyName: String, priority: Int): Policy {
        val policy = find(policyId)
        if (policyName.isBlank()) throw BusinessRuleException("정책 이름이 필요합니다")
        val before = snapshot(policy)
        policy.update(policyName.trim(), priority)
        eventPublisher.publishEvent(AdminChangeEvent("POLICY", policyId, "UPDATE", before, snapshot(policy)))
        return policy
    }

    /**
     * 대상 묶음을 통째로 바꾼다. 검사는 만들 때와 같다 (하나 이상, 대상마다 권한·리소스·역할 중 하나).
     * 그대로 남는 대상은 두고, 빠진 대상만 지우고 새 대상만 더한다. 판정은 대상을 매번 조회하므로 바로 적용된다
     */
    fun replaceTargets(policyId: Long, targets: List<PolicyTargetSpec>): List<PolicyTarget> {
        find(policyId)
        if (targets.isEmpty()) throw BusinessRuleException("정책 대상이 하나 이상 필요합니다")
        val wanted = targets.map { target(policyId, it) }.distinctBy(::targetKey)
        val current = targetRepository.findByPolicyId(policyId)
        val wantedKeys = wanted.map(::targetKey).toSet()
        val currentKeys = current.map(::targetKey).toSet()
        if (wantedKeys == currentKeys) return current
        targetRepository.deleteAll(current.filter { targetKey(it) !in wantedKeys })
        val added = targetRepository.saveAll(wanted.filter { targetKey(it) !in currentKeys })
        eventPublisher.publishEvent(
            AdminChangeEvent("POLICY", policyId, "UPDATE_TARGETS", mapOf("targets" to targetSnapshot(current)), mapOf("targets" to targetSnapshot(wanted))),
        )
        return current.filter { targetKey(it) in wantedKeys } + added
    }

    private fun targetKey(t: PolicyTarget) = PolicyTargetSpec(t.permissionId, t.resourceId, t.roleId)

    private fun targetSnapshot(targets: List<PolicyTarget>) =
        targets.map(::targetKey).sortedWith(compareBy({ it.permissionId }, { it.resourceId }, { it.roleId }))
            .map { mapOf("permissionId" to it.permissionId, "resourceId" to it.resourceId, "roleId" to it.roleId) }

    /** 끈 정책은 판정에서 빠진다 */
    fun changeActive(policyId: Long, active: Boolean): Policy {
        val policy = find(policyId)
        if (policy.isActive == active) return policy
        val before = snapshot(policy)
        policy.changeActive(active)
        eventPublisher.publishEvent(AdminChangeEvent("POLICY", policyId, if (active) "ACTIVATE" else "DEACTIVATE", before, snapshot(policy)))
        return policy
    }

    /** 예외를 지금 끝낸다. 이력이 남도록 지우지 않는다 */
    fun endException(exceptionId: Long) {
        val exception = exceptionRepository.findByIdOrNull(exceptionId) ?: throw NotFoundException("정책 예외", exceptionId)
        val now = clock.instant()
        if (exception.validUntil?.isAfter(now) == false) return
        exception.end(now)
        eventPublisher.publishEvent(
            AdminChangeEvent("POLICY", exception.policyId, "END_EXCEPTION", mapOf("exceptionId" to exceptionId, "subjectId" to exception.subjectId, "resourceId" to exception.resourceId), null),
        )
    }

    private fun find(policyId: Long): Policy = policyRepository.findByIdOrNull(policyId) ?: throw NotFoundException("정책", policyId)

    private fun snapshot(p: Policy) = mapOf("policyName" to p.policyName, "priority" to p.priority, "isActive" to p.isActive)

    fun addException(policyId: Long, subjectId: Long?, resourceId: Long?, reason: String, validUntil: Instant?): PolicyException {
        if (!policyRepository.existsById(policyId)) throw NotFoundException("정책", policyId)
        if (subjectId == null && resourceId == null) throw BusinessRuleException("예외 대상(subject 또는 리소스)이 필요합니다")
        if (reason.isBlank()) throw BusinessRuleException("예외 사유가 필요합니다")
        val exception = exceptionRepository.save(PolicyException(policyId, subjectId, resourceId, reason, clock.instant(), validUntil))
        // 예외는 정책을 그 대상에게 끄는 것과 같으므로 기준 데이터 변경으로 남긴다
        eventPublisher.publishEvent(
            AdminChangeEvent(
                "POLICY", policyId, "ADD_EXCEPTION", null,
                mapOf("exceptionId" to exception.requireId(), "subjectId" to subjectId, "resourceId" to resourceId, "reason" to reason, "validUntil" to validUntil?.toString()),
            ),
        )
        return exception
    }

    private fun target(policyId: Long, spec: PolicyTargetSpec): PolicyTarget {
        val filled = listOfNotNull(spec.permissionId, spec.resourceId, spec.roleId)
        if (filled.size != 1) throw BusinessRuleException("정책 대상은 권한·리소스·역할 중 하나만 지정합니다")
        return when {
            spec.permissionId != null -> PolicyTarget.permission(policyId, spec.permissionId)
            spec.resourceId != null -> PolicyTarget.resource(policyId, spec.resourceId)
            else -> PolicyTarget.role(policyId, filled.single())
        }
    }
}
