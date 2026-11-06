package com.didrakon.iam.risk

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.domain.Sort
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.LocalTime
import java.time.format.DateTimeParseException

/** 위험 정책 변경. 감사 모듈이 받아 기록한다. 추가면 before 가 null */
data class RiskPolicyChangedEvent(val policyId: Long, val action: String, val before: Map<String, Any?>?, val after: Map<String, Any?>)

data class RiskPolicySpec(val policyName: String, val conditionExpression: String, val riskScore: Int, val action: RiskAction)

/** 위험 정책 관리. 조건은 저장 전에 [RiskEngine] 이 읽을 수 있는 형태인지 검사한다 */
@Service
@Transactional
class RiskPolicyService(
    private val policyRepository: RiskPolicyRepository,
    private val signalRepository: RiskSignalRepository,
    private val assessmentRepository: RiskAssessmentRepository,
    private val jsonMapper: JsonMapper,
    private val eventPublisher: ApplicationEventPublisher,
) {
    @Transactional(readOnly = true)
    fun policies(): List<RiskPolicy> = policyRepository.findAll(Sort.by("riskType", "id"))

    fun create(riskType: RiskType, spec: RiskPolicySpec): RiskPolicy {
        val validated = validate(spec)
        val policy = policyRepository.save(RiskPolicy(validated.policyName, riskType, validated.conditionExpression, validated.riskScore, validated.action))
        eventPublisher.publishEvent(RiskPolicyChangedEvent(policy.requireId(), "CREATE", null, policy.snapshot()))
        return policy
    }

    fun update(policyId: Long, spec: RiskPolicySpec): RiskPolicy {
        val policy = find(policyId)
        val validated = validate(spec)
        val before = policy.snapshot()
        policy.update(validated.policyName, validated.conditionExpression, validated.riskScore, validated.action)
        eventPublisher.publishEvent(RiskPolicyChangedEvent(policyId, "UPDATE", before, policy.snapshot()))
        return policy
    }

    fun changeActive(policyId: Long, active: Boolean): RiskPolicy {
        val policy = find(policyId)
        if (policy.isActive == active) return policy
        val before = policy.snapshot()
        policy.changeActive(active)
        eventPublisher.publishEvent(RiskPolicyChangedEvent(policyId, if (active) "ACTIVATE" else "DEACTIVATE", before, policy.snapshot()))
        return policy
    }

    @Transactional(readOnly = true)
    fun recentAssessments(subjectId: Long): List<RiskAssessment> = assessmentRepository.findTop20BySubjectIdOrderByAssessedAtDesc(subjectId)

    @Transactional(readOnly = true)
    fun recentSignals(subjectId: Long): List<RiskSignal> = signalRepository.findTop20BySubjectIdOrderByDetectedAtDesc(subjectId)

    private fun find(policyId: Long): RiskPolicy = policyRepository.findByIdOrNull(policyId) ?: throw NotFoundException("위험 정책", policyId)

    /** 이름·점수 범위와 조건 JSON 을 검사하고, 조건은 공백 없이 다시 써서 돌려준다 */
    private fun validate(spec: RiskPolicySpec): RiskPolicySpec {
        val name = spec.policyName.trim()
        if (name.isEmpty()) throw BusinessRuleException("정책 이름이 필요합니다")
        if (spec.riskScore !in 0..100) throw BusinessRuleException("점수는 0~100 사이여야 합니다")
        val condition = runCatching { jsonMapper.readTree(spec.conditionExpression) }.getOrNull()
            ?.takeIf { it.isObject } ?: throw BusinessRuleException("조건은 JSON 객체여야 합니다")
        val signal = condition.path("signal").asString("")
        val type = RiskSignalType.entries.firstOrNull { it.name == signal }
            ?: throw BusinessRuleException("signal 은 ${RiskSignalType.entries.joinToString()} 중 하나여야 합니다")
        validateKeys(type, condition)
        return spec.copy(policyName = name, conditionExpression = jsonMapper.writeValueAsString(condition))
    }

    private fun validateKeys(type: RiskSignalType, condition: JsonNode) {
        when (type) {
            RiskSignalType.UNUSUAL_TIME -> listOf("from", "to").forEach { key ->
                condition.get(key)?.let { value ->
                    try {
                        LocalTime.parse(value.asString())
                    } catch (e: DateTimeParseException) {
                        throw BusinessRuleException("$key 는 HH:mm 형식이어야 합니다")
                    }
                }
            }
            RiskSignalType.FAILED_LOGIN_BURST -> positive(condition, "threshold")
            RiskSignalType.MASS_ACCESS -> listOf("threshold", "windowSeconds").forEach { positive(condition, it) }
            RiskSignalType.FOREIGN_IP -> condition.get("allowedCountries")?.let {
                if (!it.isArray || (0 until it.size()).any { i -> !it.get(i).isString }) {
                    throw BusinessRuleException("allowedCountries 는 국가 코드 배열이어야 합니다 (예: [\"KR\"])")
                }
            }
            RiskSignalType.NEW_DEVICE -> Unit
        }
    }

    private fun positive(condition: JsonNode, key: String) {
        condition.get(key)?.let { if (!it.isIntegralNumber || it.asLong() <= 0) throw BusinessRuleException("$key 는 1 이상의 정수여야 합니다") }
    }
}
