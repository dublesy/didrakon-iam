package com.didrakon.iam.governance.event

import com.didrakon.iam.governance.request.AccessRequestStatus
import com.didrakon.iam.governance.request.AccessRequestType
import com.didrakon.iam.governance.review.AccessReviewDecision

/*
 * governance 가 발행하는 도메인 이벤트. 같은 트랜잭션에서 동기적으로 전달된다.
 * 권한 자체의 변화는 RoleAssignmentChangedEvent 로 따로 남으므로, 여기서는 절차(요청·승인·비상 접근)를 알린다.
 */

/** 접근 요청이 생기거나 상태가 바뀌었다. actorId 는 요청자·승인자 등 그 변경을 한 사람 (만료는 null) */
data class AccessRequestChangedEvent(
    val requestId: Long,
    val requestType: AccessRequestType,
    val subjectId: Long,
    val roleId: Long,
    val status: AccessRequestStatus,
    val actorId: Long?,
    val comment: String?,
)

enum class BreakGlassAction { ACTIVATE, END, EXPIRE }

/** 비상 접근이 시작·종료되었다. 보안 담당자 알림 등에 쓴다 */
data class BreakGlassEvent(
    val sessionId: Long,
    val subjectId: Long,
    val roleId: Long,
    val action: BreakGlassAction,
    val actorId: Long?,
    val reason: String?,
)

enum class DelegationAction { CREATE, REVOKE }

data class DelegationEvent(
    val delegationId: Long,
    val delegatorId: Long,
    val delegateId: Long,
    val roleId: Long,
    val action: DelegationAction,
    val actorId: Long?,
    val reason: String?,
)

enum class AccessReviewAction { CREATE, ESCALATE, CLOSE }

/** 접근 재검토 캠페인이 열리거나 상위 관리자에게 넘겨지거나(ESCALATE, itemCount = 넘긴 항목 수) 닫혔다. actorId 가 null 이면 기한 경과로 스케줄러가 처리했다 */
data class AccessReviewCampaignEvent(
    val campaignId: Long,
    val name: String,
    val action: AccessReviewAction,
    val itemCount: Int,
    val actorId: Long?,
)

/**
 * 접근 재검토 항목의 결정. 증적이므로 결정마다 남긴다.
 * decidedBy 가 null 이면 기한 경과·마감으로 자동 처리된 것이고, actorId 는 그 처리를 일으킨 사람(마감한 관리자, 스케줄러면 null)이다.
 */
data class AccessReviewDecidedEvent(
    val campaignId: Long,
    val itemId: Long,
    val assignmentId: Long,
    val subjectId: Long,
    val roleId: Long,
    val decision: AccessReviewDecision,
    val decidedBy: Long?,
    val actorId: Long?,
    val comment: String?,
)
