package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.identity.event.GroupMembershipChange
import com.didrakon.iam.identity.event.GroupMembershipChangedEvent
import com.didrakon.iam.identity.event.MembershipChange
import com.didrakon.iam.identity.event.MembershipChangedEvent
import com.didrakon.iam.identity.event.MembershipUpdatedEvent
import com.didrakon.iam.identity.event.PrimaryMembershipTransferredEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/** 조직 소속·그룹 구성원 변경 → AUDIT_EVENT(MEMBERSHIP_CHANGE). 행위자는 요청 컨텍스트에서 얻는다 */
@Component
class MembershipAuditListener(
    private val auditEventWriter: AuditEventWriter,
) {
    @EventListener
    fun onMembershipChanged(event: MembershipChangedEvent) {
        val membership = mapOf("orgId" to event.orgId, "membershipType" to event.membershipType)
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.MEMBERSHIP_CHANGE,
                targetSubjectId = event.subjectId,
                resourceType = "SUBJECT_ORGANIZATION",
                resourceId = event.membershipId.toString(),
                action = if (event.change == MembershipChange.JOINED) "JOIN" else "LEAVE",
                before = membership.takeIf { event.change == MembershipChange.LEFT },
                after = membership.takeIf { event.change == MembershipChange.JOINED },
            ),
        )
    }

    @EventListener
    fun onMembershipUpdated(event: MembershipUpdatedEvent) {
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.MEMBERSHIP_CHANGE,
                targetSubjectId = event.subjectId,
                resourceType = "SUBJECT_ORGANIZATION",
                resourceId = event.membershipId.toString(),
                action = "UPDATE",
                before = event.before + ("orgId" to event.orgId),
                after = event.after + ("orgId" to event.orgId),
            ),
        )
    }

    /** 새 소속 생성(JOIN)과 별도로, 어디서 어디로 옮겼는지를 한 건으로 남긴다 */
    @EventListener
    fun onPrimaryMembershipTransferred(event: PrimaryMembershipTransferredEvent) {
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.MEMBERSHIP_CHANGE,
                targetSubjectId = event.subjectId,
                resourceType = "SUBJECT_ORGANIZATION",
                resourceId = null,
                action = "TRANSFER",
                before = event.fromOrgId?.let { mapOf("orgId" to it) },
                after = mapOf("orgId" to event.toOrgId),
            ),
        )
    }

    @EventListener
    fun onGroupMembershipChanged(event: GroupMembershipChangedEvent) {
        val group = mapOf("groupId" to event.groupId)
        auditEventWriter.write(
            AuditRecord(
                eventType = AuditEventType.MEMBERSHIP_CHANGE,
                targetSubjectId = event.subjectId,
                resourceType = "GROUP_MEMBER",
                resourceId = event.groupId.toString(),
                action = if (event.change == GroupMembershipChange.ADDED) "ADD" else "REMOVE",
                before = group.takeIf { event.change == GroupMembershipChange.REMOVED },
                after = group.takeIf { event.change == GroupMembershipChange.ADDED },
            ),
        )
    }
}
