package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.common.event.AdminChangeEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/** 기준 데이터 수정·켜기·끄기 → AUDIT_EVENT. 유형은 바뀐 대상의 성격으로 고른다 */
@Component
class AdminChangeAuditListener(private val auditEventWriter: AuditEventWriter) {
    @EventListener
    fun onAdminChange(event: AdminChangeEvent) {
        auditEventWriter.write(
            AuditRecord(
                eventType = typeOf(event.target),
                targetSubjectId = event.targetSubjectId ?: event.targetId.takeIf { event.target == "USER" },
                resourceType = event.target,
                resourceId = event.targetId.toString(),
                action = event.action,
                before = event.before,
                after = event.after,
            ),
        )
    }

    private fun typeOf(target: String): AuditEventType = when (target) {
        "ROLE" -> AuditEventType.ROLE_CHANGE
        "RESOURCE", "PERMISSION", "SCOPE" -> AuditEventType.PERMISSION_CHANGE
        "USER", "ORGANIZATION", "GROUP" -> AuditEventType.MEMBERSHIP_CHANGE
        else -> AuditEventType.POLICY_CHANGE // POLICY, ROLE_CONFLICT, CLIENT, WEBHOOK
    }
}
