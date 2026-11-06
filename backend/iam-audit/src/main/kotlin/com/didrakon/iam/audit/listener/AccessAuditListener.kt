package com.didrakon.iam.audit.listener

import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.audit.record.AuditEventWriter
import com.didrakon.iam.audit.record.AuditRecord
import com.didrakon.iam.authn.event.LoggedOutEvent
import com.didrakon.iam.authn.event.LoginFailedEvent
import com.didrakon.iam.authn.event.LoginSucceededEvent
import com.didrakon.iam.authn.event.MfaVerifiedEvent
import com.didrakon.iam.authn.event.PasskeyChangedEvent
import com.didrakon.iam.authn.event.PasswordResetEvent
import com.didrakon.iam.governance.event.AccessRequestChangedEvent
import com.didrakon.iam.governance.event.AccessReviewCampaignEvent
import com.didrakon.iam.governance.event.AccessReviewDecidedEvent
import com.didrakon.iam.governance.event.BreakGlassEvent
import com.didrakon.iam.governance.event.DelegationEvent
import com.didrakon.iam.governance.request.AccessRequestStatus
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component

/**
 * 로그인(authn)과 권한 절차(governance)를 AUDIT_EVENT 로 남긴다.
 * 로그인 기록은 HTTP 요청 중이라 업무 트랜잭션이 없어 바로 커밋된다. 상세 인증 이력은 AUTHENTICATION_EVENT 에 따로 있다.
 */
@Component
class AccessAuditListener(
    private val auditEventWriter: AuditEventWriter,
) {
    @EventListener
    fun onLoginSucceeded(event: LoginSucceededEvent) = write(
        AuditEventType.LOGIN, event.subjectId, event.subjectId, "LOGIN_SESSION", event.loginSessionId.toString(), "LOGIN_SUCCESS",
    )

    /** 없는 계정의 실패도 남긴다. 어떤 로그인 ID 로 시도했는지가 공격 탐지에 필요하다 */
    @EventListener
    fun onLoginFailed(event: LoginFailedEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.LOGIN,
            actorSubjectId = event.subjectId,
            targetSubjectId = event.subjectId,
            resourceType = "LOCAL_CREDENTIAL",
            resourceId = null,
            action = "LOGIN_FAILURE",
            after = mapOf("loginId" to event.loginId, "ipAddress" to event.ipAddress),
            reason = event.reason,
        ),
    )

    @EventListener
    fun onLoggedOut(event: LoggedOutEvent) = write(
        AuditEventType.LOGOUT, event.subjectId, event.subjectId, "LOGIN_SESSION", event.loginSessionId?.toString(), "LOGOUT",
    )

    @EventListener
    fun onMfaVerified(event: MfaVerifiedEvent) = write(
        AuditEventType.LOGIN, event.subjectId, event.subjectId, "MFA", null, if (event.success) "MFA_SUCCESS" else "MFA_FAILURE",
    )

    /** 패스키 등록·삭제. 로그인 수단이 바뀐 일이라 LOGIN 유형으로 남긴다 (본인만 할 수 있다) */
    @EventListener
    fun onPasskeyChanged(event: PasskeyChangedEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.LOGIN,
            actorSubjectId = event.subjectId,
            targetSubjectId = event.subjectId,
            resourceType = "PASSKEY",
            resourceId = event.credentialId.take(200),
            action = if (event.added) "PASSKEY_ADD" else "PASSKEY_REMOVE",
            after = mapOf("label" to event.label),
        ),
    )

    /** 셀프 비밀번호 재설정의 본인 확인. 로그인 실패처럼 없는 계정의 시도도 남긴다 */
    @EventListener
    fun onPasswordReset(event: PasswordResetEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.LOGIN,
            actorSubjectId = event.subjectId,
            targetSubjectId = event.subjectId,
            resourceType = "LOCAL_CREDENTIAL",
            resourceId = null,
            action = if (event.success) "PASSWORD_RESET_SUCCESS" else "PASSWORD_RESET_FAILURE",
            after = mapOf("loginId" to event.loginId, "ipAddress" to event.ipAddress),
            reason = event.reason,
        ),
    )

    @EventListener
    fun onAccessRequestChanged(event: AccessRequestChangedEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.JIT,
            actorSubjectId = event.actorId,
            targetSubjectId = event.subjectId,
            resourceType = "ACCESS_REQUEST",
            resourceId = event.requestId.toString(),
            action = if (event.status == AccessRequestStatus.PENDING) "REQUEST" else event.status.name,
            after = mapOf("requestType" to event.requestType, "roleId" to event.roleId, "status" to event.status),
            reason = event.comment,
        ),
    )

    @EventListener
    fun onBreakGlass(event: BreakGlassEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.JIT,
            actorSubjectId = event.actorId,
            targetSubjectId = event.subjectId,
            resourceType = "BREAK_GLASS_SESSION",
            resourceId = event.sessionId.toString(),
            action = "BREAK_GLASS_${event.action}",
            after = mapOf("roleId" to event.roleId),
            reason = event.reason,
        ),
    )

    @EventListener
    fun onDelegation(event: DelegationEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.ROLE_CHANGE,
            actorSubjectId = event.actorId,
            targetSubjectId = event.delegateId,
            resourceType = "DELEGATION",
            resourceId = event.delegationId.toString(),
            action = "DELEGATION_${event.action}",
            after = mapOf("delegatorId" to event.delegatorId, "roleId" to event.roleId),
            reason = event.reason,
        ),
    )

    /** 접근 재검토 캠페인 생성·마감. 결정 하나하나는 아래 항목 기록에 남는다 */
    @EventListener
    fun onAccessReviewCampaign(event: AccessReviewCampaignEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.ROLE_CHANGE,
            actorSubjectId = event.actorId,
            targetSubjectId = null,
            resourceType = "ACCESS_REVIEW_CAMPAIGN",
            resourceId = event.campaignId.toString(),
            action = "REVIEW_CAMPAIGN_${event.action}",
            after = mapOf("name" to event.name, "itemCount" to event.itemCount),
        ),
    )

    /** 접근 재검토 결정. 정기 점검 증적이므로 자동 처리(decidedBy 없음)도 남긴다 */
    @EventListener
    fun onAccessReviewDecided(event: AccessReviewDecidedEvent) = auditEventWriter.write(
        AuditRecord(
            eventType = AuditEventType.ROLE_CHANGE,
            actorSubjectId = event.actorId,
            targetSubjectId = event.subjectId,
            resourceType = "ACCESS_REVIEW_ITEM",
            resourceId = event.itemId.toString(),
            action = "REVIEW_${event.decision}",
            after = mapOf(
                "campaignId" to event.campaignId,
                "assignmentId" to event.assignmentId,
                "roleId" to event.roleId,
                "decision" to event.decision,
                "decidedBy" to event.decidedBy,
                "automatic" to (event.decidedBy == null),
            ),
            reason = event.comment,
        ),
    )

    private fun write(type: AuditEventType, actor: Long?, target: Long?, resourceType: String, resourceId: String?, action: String) =
        auditEventWriter.write(AuditRecord(type, target, resourceType, resourceId, action, actorSubjectId = actor))
}
