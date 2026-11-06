package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.history.PolicyChangeHistory
import com.didrakon.iam.audit.history.PolicyChangeHistoryRepository
import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyRuleRepository
import com.didrakon.iam.authz.policy.PolicyVersion
import com.didrakon.iam.authz.policy.PolicyVersionActivatedEvent
import com.didrakon.iam.authz.policy.PolicyVersionRepository
import com.didrakon.iam.common.context.RequestContextHolder
import org.springframework.context.event.EventListener
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import java.time.Clock

/** 정책 버전 활성화 → POLICY_CHANGE_HISTORY(규칙 스냅샷) + AUDIT_EVENT(POLICY_CHANGE) */
@Component
class PolicyAuditListener(
    private val historyRepository: PolicyChangeHistoryRepository,
    private val policyRepository: PolicyRepository,
    private val versionRepository: PolicyVersionRepository,
    private val ruleRepository: PolicyRuleRepository,
    private val auditEventWriter: AuditEventWriter,
    private val jsonMapper: JsonMapper,
    private val clock: Clock,
) {
    @EventListener
    fun onPolicyVersionActivated(event: PolicyVersionActivatedEvent) {
        val previous = event.previousVersionId?.let { versionRepository.findByIdOrNull(it) }
        val activated = versionRepository.findByIdOrNull(event.activatedVersionId)
            ?: throw IllegalStateException("활성화된 정책 버전이 없습니다: ${event.activatedVersionId}")
        val changedBy = RequestContextHolder.current()?.actorSubjectId ?: event.versionCreatedBy

        historyRepository.save(
            PolicyChangeHistory(
                policyId = event.policyId,
                oldVersion = previous?.version,
                newVersion = activated.version,
                changedBy = changedBy,
                changeReason = event.changeReason,
                oldValue = previous?.let(::snapshot),
                newValue = snapshot(activated),
                changedAt = clock.instant(),
            ),
        )
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.POLICY_CHANGE,
                actorSubjectId = changedBy,
                targetSubjectId = null,
                resourceType = "POLICY",
                resourceId = event.policyId.toString(),
                action = "ACTIVATE",
                before = previous?.let { mapOf("version" to it.version) },
                after = mapOf("version" to activated.version),
                reason = event.changeReason,
            ),
        )
    }

    /** 그 버전이 실제로 무엇을 판정했는지 나중에 재현할 수 있도록 효과와 규칙 전체를 남긴다 */
    private fun snapshot(version: PolicyVersion): String {
        val policy = policyRepository.findByIdOrNull(version.policyId)
        val rules = ruleRepository.findByPolicyVersionIdIn(listOf(version.requireId()))
            .sortedWith(compareBy({ it.ruleGroup }, { it.ruleOrder }))
            .map {
                mapOf(
                    "ruleGroup" to it.ruleGroup,
                    "attributeSource" to it.attributeSource,
                    "attributeName" to it.attributeName,
                    "operator" to it.operator,
                    "attributeValue" to it.attributeValue?.let(jsonMapper::readTree),
                    "ruleOrder" to it.ruleOrder,
                )
            }
        return jsonMapper.writeValueAsString(
            mapOf("version" to version.version, "effect" to policy?.effect, "rules" to rules),
        )
    }
}
