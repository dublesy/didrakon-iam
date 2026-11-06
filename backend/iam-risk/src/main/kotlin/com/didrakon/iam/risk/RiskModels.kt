package com.didrakon.iam.risk

import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant

/** 어떤 상황을 평가하는가 */
enum class RiskType { LOGIN, DATA_ACCESS, PRIVILEGE, JIT }

/** 위험 정책이 권하는 조치. 뒤에 올수록 강하다 */
enum class RiskAction { ALLOW, CHALLENGE, APPROVAL, DENY }

enum class RiskSignalType { NEW_DEVICE, FOREIGN_IP, UNUSUAL_TIME, FAILED_LOGIN_BURST, MASS_ACCESS }

/**
 * 위험 정책: 조건(condition_expression)에 맞는 신호가 잡히면 점수를 더하고 조치를 권한다.
 * 조건 예: {"signal":"UNUSUAL_TIME","from":"07:00","to":"22:00"}. 쓸 수 있는 키는 [RiskEngine] 참고
 */
@Entity
@Table(name = "risk_policy")
class RiskPolicy(
    policyName: String,
    riskType: RiskType,
    conditionExpression: String,
    riskScore: Int,
    action: RiskAction,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "risk_policy_id")
    override val id: Long? = null

    @Column(name = "policy_name", nullable = false, length = 200)
    var policyName: String = policyName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_type", nullable = false, length = 30)
    var riskType: RiskType = riskType
        protected set

    @Column(name = "condition_expression", nullable = false, columnDefinition = "json")
    var conditionExpression: String = conditionExpression
        protected set

    @Column(name = "risk_score", nullable = false)
    var riskScore: Int = riskScore
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 30)
    var action: RiskAction = action
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun update(policyName: String, conditionExpression: String, riskScore: Int, action: RiskAction) {
        this.policyName = policyName
        this.conditionExpression = conditionExpression
        this.riskScore = riskScore
        this.action = action
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    /** 감사 기록의 before·after */
    fun snapshot(): Map<String, Any?> = mapOf(
        "policyName" to policyName,
        "riskType" to riskType.name,
        "conditionExpression" to conditionExpression,
        "riskScore" to riskScore,
        "action" to action.name,
        "isActive" to isActive,
    )

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 감지된 위험 신호 한 건 */
@Entity
@Table(name = "risk_signal")
class RiskSignal(
    subjectId: Long,
    signalType: RiskSignalType,
    riskScore: Int,
    details: String?,
    detectedAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "risk_signal_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Enumerated(EnumType.STRING)
    @Column(name = "signal_type", nullable = false, length = 30, updatable = false)
    val signalType: RiskSignalType = signalType

    @Column(name = "risk_score", nullable = false, updatable = false)
    val riskScore: Int = riskScore

    @Column(name = "details", columnDefinition = "json", updatable = false)
    val details: String? = details

    @Column(name = "detected_at", nullable = false, updatable = false)
    val detectedAt: Instant = detectedAt

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 평가 결과 한 건. 접근 요청 평가면 request_id 가 붙는다 */
@Entity
@Table(name = "risk_assessment")
class RiskAssessment(
    subjectId: Long,
    requestId: Long?,
    riskScore: Int,
    riskLevel: RiskLevel,
    decision: RiskAction,
    assessedAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "assessment_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "request_id", updatable = false)
    val requestId: Long? = requestId

    @Column(name = "risk_score", nullable = false, updatable = false)
    val riskScore: Int = riskScore

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 30, updatable = false)
    val riskLevel: RiskLevel = riskLevel

    @Enumerated(EnumType.STRING)
    @Column(name = "decision", nullable = false, length = 30, updatable = false)
    val decision: RiskAction = decision

    @Column(name = "assessed_at", nullable = false, updatable = false)
    val assessedAt: Instant = assessedAt

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

interface RiskPolicyRepository : JpaRepository<RiskPolicy, Long> {
    fun findByRiskTypeAndIsActiveTrue(riskType: RiskType): List<RiskPolicy>
}

interface RiskSignalRepository : JpaRepository<RiskSignal, Long> {
    fun findBySubjectIdOrderByDetectedAtDesc(subjectId: Long): List<RiskSignal>

    fun findTop20BySubjectIdOrderByDetectedAtDesc(subjectId: Long): List<RiskSignal>
}

interface RiskAssessmentRepository : JpaRepository<RiskAssessment, Long> {
    fun findBySubjectIdOrderByAssessedAtDesc(subjectId: Long): List<RiskAssessment>

    fun findTop20BySubjectIdOrderByAssessedAtDesc(subjectId: Long): List<RiskAssessment>

    fun findByRequestId(requestId: Long): RiskAssessment?
}
