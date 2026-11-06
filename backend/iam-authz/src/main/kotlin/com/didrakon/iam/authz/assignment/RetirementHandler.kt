package com.didrakon.iam.authz.assignment

import com.didrakon.iam.identity.event.SubjectStatusChangedEvent
import com.didrakon.iam.identity.subject.SubjectStatus
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/**
 * 퇴사하면 남은 역할 할당(직접·임시·위임·비상)을 모두 회수한다. 조직·그룹 할당은 소속이 끝나며 이미 회수되었다.
 * 사용 안 함은 되돌릴 수 있으므로 할당을 남겨 둔다 (판정은 PDP 가 상태로 막는다)
 */
@Component
class RetirementHandler(private val assignmentService: RoleAssignmentService) {
    @EventListener
    fun onStatusChanged(event: SubjectStatusChangedEvent) {
        if (event.status == SubjectStatus.RETIRED) assignmentService.revokeAllFor(event.subjectId, "퇴사")
    }
}
