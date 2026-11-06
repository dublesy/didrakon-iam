package com.didrakon.iam.risk

import com.didrakon.iam.common.RiskLevel
import org.slf4j.LoggerFactory
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Clock
import java.time.Instant
import java.time.LocalTime

/**
 * 평가할 상황. 호출 측이 아는 사실만 채운다. 비어 있는 사실로는 신호를 만들지 않는다.
 * [accessCountSince] 는 MASS_ACCESS 정책이 있을 때만 부른다 (조회 구간은 정책이 정한다).
 */
class RiskContext(
    val subjectId: Long,
    val type: RiskType,
    val ipAddress: String? = null,
    val knownDevice: Boolean? = null,
    val consecutiveFailures: Int? = null,
    val accessCountSince: ((Instant) -> Long)? = null,
)

data class DetectedSignal(
    val policyId: Long,
    val policyName: String,
    val type: RiskSignalType,
    val score: Int,
    val action: RiskAction,
    val details: Map<String, Any?>,
)

data class RiskOutcome(val score: Int, val level: RiskLevel, val decision: RiskAction, val signals: List<DetectedSignal>) {
    val reason: String get() = signals.joinToString(", ") { it.policyName }.ifEmpty { "감지된 신호 없음" }
}

/** IP → 국가 코드(ISO 3166-1 alpha-2). 구현이 없으면 FOREIGN_IP 신호를 만들지 않는다 */
fun interface IpLocationResolver {
    fun countryOf(ipAddress: String): String?
}

/**
 * 위험 평가 엔진. [RiskType] 이 같은 활성 정책 중 신호가 잡힌 정책의 점수를 더하고(최대 100),
 * 조치는 그중 가장 강한 것을 택한다. 점수가 [DENY_SCORE] 이상이면 정책과 관계없이 DENY 다.
 *
 * 조건 키 (condition_expression):
 * - NEW_DEVICE: 없음. 이 subject 가 처음 쓰는 기기
 * - FOREIGN_IP: allowedCountries (기본 ["KR"])
 * - UNUSUAL_TIME: from, to (기본 07:00~22:00, 서버 시간대 기준). 이 범위 밖이면 신호
 * - FAILED_LOGIN_BURST: threshold (기본 3). 직전 연속 실패 횟수
 * - MASS_ACCESS: threshold (기본 100), windowSeconds (기본 60). 구간 안의 권한 판정 횟수
 */
@Service
@Transactional
class RiskEngine(
    private val policyRepository: RiskPolicyRepository,
    private val signalRepository: RiskSignalRepository,
    private val assessmentRepository: RiskAssessmentRepository,
    private val jsonMapper: JsonMapper,
    private val clock: Clock,
    private val ipLocationResolver: IpLocationResolver? = null,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    /** 평가하고, 신호가 있으면 신호와 평가를 남긴다 */
    fun assess(context: RiskContext): RiskOutcome =
        evaluate(context).also { if (it.signals.isNotEmpty()) record(context.subjectId, it) }

    /** 저장하지 않고 평가만 한다. 평가 대상(접근 요청 등)이 저장된 뒤 [record] 로 남길 때 쓴다 */
    @Transactional(readOnly = true)
    fun evaluate(context: RiskContext): RiskOutcome {
        val now = clock.instant()
        val signals = policyRepository.findByRiskTypeAndIsActiveTrue(context.type).mapNotNull { policy ->
            val condition = parse(policy) ?: return@mapNotNull null
            val type = runCatching { RiskSignalType.valueOf(condition.path("signal").asString()) }.getOrNull()
                ?: return@mapNotNull null.also { log.warn("위험 정책 {} 의 signal 이 올바르지 않습니다", policy.id) }
            detect(type, condition, context, now)?.let { DetectedSignal(policy.requireId(), policy.policyName, type, policy.riskScore, policy.action, it) }
        }
        val score = signals.sumOf { it.score }.coerceIn(0, 100)
        val strongest = signals.maxOfOrNull { it.action } ?: RiskAction.ALLOW
        val decision = if (score >= DENY_SCORE) RiskAction.DENY else strongest
        return RiskOutcome(score, levelOf(score), decision, signals)
    }

    fun record(subjectId: Long, outcome: RiskOutcome, requestId: Long? = null) {
        val now = clock.instant()
        signalRepository.saveAll(
            outcome.signals.map {
                RiskSignal(subjectId, it.type, it.score, jsonMapper.writeValueAsString(it.details + ("policyId" to it.policyId)), now)
            },
        )
        assessmentRepository.save(RiskAssessment(subjectId, requestId, outcome.score, outcome.level, outcome.decision, now))
    }

    /** 신호가 잡히면 근거(details), 아니면 null */
    private fun detect(type: RiskSignalType, condition: JsonNode, context: RiskContext, now: Instant): Map<String, Any?>? = when (type) {
        RiskSignalType.NEW_DEVICE -> if (context.knownDevice == false) emptyMap() else null

        RiskSignalType.FOREIGN_IP -> {
            val country = context.ipAddress?.let { ipLocationResolver?.countryOf(it) }
            val list = condition.path("allowedCountries")
            val allowed: List<String> = if (list.isArray) (0 until list.size()).map { list.get(it).asString() } else listOf("KR")
            if (country != null && country !in allowed) mapOf("ip" to context.ipAddress, "country" to country) else null
        }

        RiskSignalType.UNUSUAL_TIME -> {
            val time = now.atZone(clock.zone).toLocalTime()
            val from = LocalTime.parse(condition.path("from").asString("07:00"))
            val to = LocalTime.parse(condition.path("to").asString("22:00"))
            if (time.isBefore(from) || !time.isBefore(to)) mapOf("time" to time.withNano(0).toString()) else null
        }

        RiskSignalType.FAILED_LOGIN_BURST -> {
            val threshold = condition.path("threshold").asInt(3)
            context.consecutiveFailures?.takeIf { it >= threshold }?.let { mapOf("failures" to it) }
        }

        RiskSignalType.MASS_ACCESS -> {
            val threshold = condition.path("threshold").asLong(100)
            val window = condition.path("windowSeconds").asLong(60)
            context.accessCountSince?.invoke(now.minusSeconds(window))?.takeIf { it >= threshold }
                ?.let { mapOf("count" to it, "windowSeconds" to window) }
        }
    }

    /** 조건 JSON 이 깨진 정책 하나 때문에 로그인 전체가 막히지 않도록 건너뛴다 */
    private fun parse(policy: RiskPolicy): JsonNode? =
        runCatching { jsonMapper.readTree(policy.conditionExpression) }
            .onFailure { log.warn("위험 정책 {} 의 조건을 읽을 수 없습니다", policy.id) }
            .getOrNull()

    companion object {
        const val DENY_SCORE = 80

        fun levelOf(score: Int): RiskLevel = when {
            score >= DENY_SCORE -> RiskLevel.CRITICAL
            score >= 50 -> RiskLevel.HIGH
            score >= 20 -> RiskLevel.MEDIUM
            else -> RiskLevel.LOW
        }
    }
}
