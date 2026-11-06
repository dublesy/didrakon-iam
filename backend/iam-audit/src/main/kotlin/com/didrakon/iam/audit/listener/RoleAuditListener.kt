package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.history.RoleChangeHistory
import com.didrakon.iam.audit.history.RoleChangeHistoryRepository
import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.authz.assignment.RoleAssignmentChangedEvent
import com.didrakon.iam.common.context.RequestContextHolder
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component
import java.time.Clock

/** 역할 할당 변경 → ROLE_CHANGE_HISTORY + AUDIT_EVENT(ROLE_CHANGE). 같은 트랜잭션에서 쓴다 */
@Component
class RoleAuditListener(
    private val historyRepository: RoleChangeHistoryRepository,
    private val auditEventWriter: AuditEventWriter,
    private val clock: Clock,
) {
    @EventListener
    fun onRoleAssignmentChanged(event: RoleAssignmentChangedEvent) {
        // 규칙·전적 등 시스템이 바꾼 할당은 그 변경을 일으킨 요청의 행위자로 남긴다
        val changedBy = event.changedBy ?: RequestContextHolder.current()?.actorSubjectId
        historyRepository.save(
            RoleChangeHistory(event.roleId, event.subjectId, event.changeType, event.assignmentId, changedBy, event.reason, clock.instant()),
        )
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.ROLE_CHANGE,
                actorSubjectId = changedBy,
                targetSubjectId = event.subjectId,
                resourceType = "ROLE_ASSIGNMENT",
                resourceId = event.assignmentId.toString(),
                action = event.changeType.name,
                after = mapOf("roleId" to event.roleId, "scopeId" to event.scopeId, "sourceType" to event.sourceType),
                reason = event.reason,
            ),
        )
    }
}
