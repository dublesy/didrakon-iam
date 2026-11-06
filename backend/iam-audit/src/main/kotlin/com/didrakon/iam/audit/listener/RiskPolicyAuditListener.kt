package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.risk.RiskPolicyChangedEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/** 위험 정책 추가·수정·켜기·끄기 → AUDIT_EVENT(POLICY_CHANGE, resource_type = RISK_POLICY) */
@Component
class RiskPolicyAuditListener(private val auditEventWriter: AuditEventWriter) {
    @EventListener
    fun onRiskPolicyChanged(event: RiskPolicyChangedEvent) {
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.POLICY_CHANGE,
                targetSubjectId = null,
                resourceType = "RISK_POLICY",
                resourceId = event.policyId.toString(),
                action = event.action,
                before = event.before,
                after = event.after,
            ),
        )
    }
}
