package com.didrakon.iam.identity.subject

import com.didrakon.iam.common.RiskLevel
import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.Table

@Entity
@Table(name = "ai_agent")
@DiscriminatorValue("AI_AGENT")
@PrimaryKeyJoinColumn(name = "subject_id")
class AiAgent(
    agentName: String,
    ownerSubjectId: Long,
    riskLevel: RiskLevel,
    agentType: String? = null,
    modelName: String? = null,
    isAutonomous: Boolean = false,
) : Subject(subjectName = agentName) {
    override val subjectType: SubjectType get() = SubjectType.AI_AGENT

    @Column(name = "agent_name", nullable = false, length = 200)
    var agentName: String = agentName
        protected set

    @Column(name = "agent_type", length = 100)
    var agentType: String? = agentType
        protected set

    /** 책임자. 다른 애그리거트라 ID 로만 참조한다 */
    @Column(name = "owner_subject_id", nullable = false)
    var ownerSubjectId: Long = ownerSubjectId
        protected set

    @Column(name = "model_name", length = 200)
    var modelName: String? = modelName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", nullable = false, length = 30)
    var riskLevel: RiskLevel = riskLevel
        protected set

    /** 사람 확인 없이 스스로 행동하는지 */
    @Column(name = "is_autonomous", nullable = false)
    var isAutonomous: Boolean = isAutonomous
        protected set
}
