package com.didrakon.iam.webhook

import com.didrakon.iam.authn.event.PasskeyChangedEvent
import com.didrakon.iam.authz.assignment.RoleAssignmentChangedEvent
import com.didrakon.iam.authz.policy.PolicyVersionActivatedEvent
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.governance.event.AccessRequestChangedEvent
import com.didrakon.iam.governance.event.AccessReviewCampaignEvent
import com.didrakon.iam.identity.event.OrganizationMovedEvent
import com.didrakon.iam.risk.RiskPolicyChangedEvent
import com.didrakon.iam.identity.event.GroupMembershipChangedEvent
import com.didrakon.iam.identity.event.MembershipChangedEvent
import com.didrakon.iam.identity.event.MembershipUpdatedEvent
import com.didrakon.iam.identity.event.PrimaryMembershipTransferredEvent
import com.didrakon.iam.identity.event.SubjectStatusChangedEvent
import org.springframework.context.event.EventListener
import org.springframework.stereotype.Component
import tools.jackson.databind.json.JsonMapper
import java.time.Clock
import java.util.UUID

/** 연동 시스템에 보내는 이벤트 유형 */
object WebhookEventTypes {
    const val ALL = "*"
    const val USER_STATUS_CHANGED = "user.status_changed"
    const val MEMBERSHIP_CHANGED = "membership.changed"
    const val GROUP_MEMBERSHIP_CHANGED = "group_membership.changed"
    const val ROLE_ASSIGNMENT_CHANGED = "role_assignment.changed"
    const val ACCESS_REQUEST_CHANGED = "access_request.changed"
    const val CONFIG_CHANGED = "config.changed"
    const val ORGANIZATION_MOVED = "organization.moved"
    const val CREDENTIAL_CHANGED = "user.credential_changed"
    const val ACCESS_REVIEW_CHANGED = "access_review.changed"

    /** 구독 확인용. 구독 유형과 관계없이 요청한 구독에만 보낸다 */
    const val TEST = "webhook.test"

    /** 구독할 수 있는 유형 */
    val SUBSCRIBABLE = listOf(
        USER_STATUS_CHANGED, MEMBERSHIP_CHANGED, GROUP_MEMBERSHIP_CHANGED, ROLE_ASSIGNMENT_CHANGED, ACCESS_REQUEST_CHANGED, CONFIG_CHANGED,
        ORGANIZATION_MOVED, CREDENTIAL_CHANGED, ACCESS_REVIEW_CHANGED,
    )
}

/**
 * 아웃박스. 도메인 이벤트를 받아 같은 트랜잭션에서 켜진 구독마다 webhook_delivery(PENDING) 를 쓴다.
 * 업무 변경이 롤백되면 전달 행도 함께 없어지고, 실제 전송은 [WebhookDispatcher] 가 커밋된 행만 보고 한다.
 * 본문에는 ID 와 짧은 코드 값만 넣는다 (이름·연락처 등 개인정보, 변경 전후 값은 넣지 않는다. 자세한 내용은 API 로 조회)
 */
@Component
class WebhookOutbox(
    private val repository: WebhookRepository,
    private val jsonMapper: JsonMapper,
    private val clock: Clock,
) {
    @EventListener
    fun on(e: SubjectStatusChangedEvent) =
        publish(WebhookEventTypes.USER_STATUS_CHANGED, mapOf("subjectId" to e.subjectId, "status" to e.status.name))

    @EventListener
    fun on(e: MembershipChangedEvent) = publish(
        WebhookEventTypes.MEMBERSHIP_CHANGED,
        mapOf(
            "subjectId" to e.subjectId, "membershipId" to e.membershipId, "orgId" to e.orgId,
            "membershipType" to e.membershipType.name, "change" to e.change.name,
        ),
    )

    @EventListener
    fun on(e: MembershipUpdatedEvent) = publish(
        WebhookEventTypes.MEMBERSHIP_CHANGED,
        mapOf("subjectId" to e.subjectId, "membershipId" to e.membershipId, "orgId" to e.orgId, "change" to "UPDATED"),
    )

    @EventListener
    fun on(e: PrimaryMembershipTransferredEvent) = publish(
        WebhookEventTypes.MEMBERSHIP_CHANGED,
        mapOf("subjectId" to e.subjectId, "fromOrgId" to e.fromOrgId, "toOrgId" to e.toOrgId, "change" to "TRANSFERRED"),
    )

    @EventListener
    fun on(e: GroupMembershipChangedEvent) = publish(
        WebhookEventTypes.GROUP_MEMBERSHIP_CHANGED,
        mapOf("groupId" to e.groupId, "subjectId" to e.subjectId, "change" to e.change.name),
    )

    @EventListener
    fun on(e: RoleAssignmentChangedEvent) = publish(
        WebhookEventTypes.ROLE_ASSIGNMENT_CHANGED,
        mapOf(
            "assignmentId" to e.assignmentId, "subjectId" to e.subjectId, "roleId" to e.roleId, "scopeId" to e.scopeId,
            "sourceType" to e.sourceType.name, "changeType" to e.changeType.name,
        ),
    )

    @EventListener
    fun on(e: AccessRequestChangedEvent) = publish(
        WebhookEventTypes.ACCESS_REQUEST_CHANGED,
        mapOf(
            "requestId" to e.requestId, "requestType" to e.requestType.name, "subjectId" to e.subjectId,
            "roleId" to e.roleId, "status" to e.status.name,
        ),
    )

    /** 전후 값은 보내지 않는다. 받는 쪽이 필요하면 API 로 조회한다 */
    @EventListener
    fun on(e: AdminChangeEvent) =
        publish(WebhookEventTypes.CONFIG_CHANGED, mapOf("target" to e.target, "targetId" to e.targetId, "action" to e.action))

    /** 위험 정책 변경은 AdminChangeEvent 를 내지 않으므로(risk 는 자체 이벤트) 설정 변경으로 따로 보낸다 */
    @EventListener
    fun on(e: RiskPolicyChangedEvent) =
        publish(WebhookEventTypes.CONFIG_CHANGED, mapOf("target" to "RISK_POLICY", "targetId" to e.policyId, "action" to e.action))

    /** 접근 정책의 새 버전 활성화 (권한 판정 규칙이 바뀐다) */
    @EventListener
    fun on(e: PolicyVersionActivatedEvent) = publish(
        WebhookEventTypes.CONFIG_CHANGED,
        mapOf("target" to "POLICY", "targetId" to e.policyId, "action" to "ACTIVATE_VERSION", "versionId" to e.activatedVersionId),
    )

    /** 조직 이동. 하위 조직도 함께 옮겨지므로 영향받는 조직 ID 를 모두 준다 */
    @EventListener
    fun on(e: OrganizationMovedEvent) =
        publish(WebhookEventTypes.ORGANIZATION_MOVED, mapOf("orgId" to e.orgId, "subtreeOrgIds" to e.subtreeOrgIds))

    /** 패스키 등록·삭제. 인증 수단 변경은 계정 탈취 징후일 수 있어 알린다 (자격 증명 ID·이름은 보내지 않는다) */
    @EventListener
    fun on(e: PasskeyChangedEvent) = publish(
        WebhookEventTypes.CREDENTIAL_CHANGED,
        mapOf("subjectId" to e.subjectId, "credentialType" to "PASSKEY", "change" to if (e.added) "ADDED" else "REMOVED"),
    )

    /** 접근 재검토 캠페인 시작·이관·마감. 항목 결정은 회수되면 역할 할당 변경으로도 나간다 */
    @EventListener
    fun on(e: AccessReviewCampaignEvent) = publish(
        WebhookEventTypes.ACCESS_REVIEW_CHANGED,
        mapOf("campaignId" to e.campaignId, "action" to e.action.name, "itemCount" to e.itemCount),
    )

    /** 구독 확인용 이벤트를 [subscription] 한 곳에만 넣는다. 전달 ID 를 돌려준다 */
    fun enqueueTest(subscription: WebhookSubscription): Long {
        val (eventId, payload) = payload(WebhookEventTypes.TEST, mapOf("subscriptionId" to subscription.subscriptionId))
        return repository.insertDelivery(subscription.subscriptionId, eventId, WebhookEventTypes.TEST, payload, clock.instant())
    }

    private fun publish(type: String, data: Map<String, Any?>) {
        val targets = repository.activeSubscriptions().filter { it.accepts(type) }
        if (targets.isEmpty()) return
        val (eventId, payload) = payload(type, data)
        val now = clock.instant()
        targets.forEach { repository.insertDelivery(it.subscriptionId, eventId, type, payload, now) }
    }

    private fun payload(type: String, data: Map<String, Any?>): Pair<String, String> {
        val eventId = UUID.randomUUID().toString()
        val body = mapOf("id" to eventId, "type" to type, "occurredAt" to clock.instant().toString(), "data" to data)
        return eventId to jsonMapper.writeValueAsString(body)
    }
}
