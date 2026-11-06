package com.didrakon.iam.identity.event

import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.subject.SubjectStatus

/*
 * identity 가 발행하는 도메인 이벤트. 같은 트랜잭션 안에서 동기적으로 전달된다.
 * authz 는 이 이벤트로 조직·그룹 역할 할당을 맞추고, audit 는 감사 기록을 남긴다 (identity 는 둘을 모른다).
 */

/** subject 의 조직 소속이 생기거나(JOINED) 끝났다(LEFT) */
data class MembershipChangedEvent(
    val subjectId: Long,
    val membershipId: Long,
    val orgId: Long,
    val membershipType: MembershipType,
    val change: MembershipChange,
)

enum class MembershipChange { JOINED, LEFT }

/** 소속은 그대로이고 직위·직급·조직장 여부만 바뀌었다. before/after 는 바뀐 항목의 값 */
data class MembershipUpdatedEvent(
    val subjectId: Long,
    val membershipId: Long,
    val orgId: Long,
    val before: Map<String, Any?>,
    val after: Map<String, Any?>,
)

/** PRIMARY 소속이 다른 조직으로 옮겨졌다 (전적·전보). 이전 PRIMARY 소속이 없었으면 fromOrgId 는 null */
data class PrimaryMembershipTransferredEvent(val subjectId: Long, val fromOrgId: Long?, val toOrgId: Long)

/** 조직이 하위 조직과 함께 다른 상위 조직 아래로 옮겨졌다. subtreeOrgIds 는 자기 자신 포함 */
data class OrganizationMovedEvent(val orgId: Long, val subtreeOrgIds: List<Long>)

/** subject 가 그룹에 들어오거나(ADDED) 나갔다(REMOVED) */
data class GroupMembershipChangedEvent(val groupId: Long, val subjectId: Long, val change: GroupMembershipChange)

enum class GroupMembershipChange { ADDED, REMOVED }

/**
 * subject 상태가 바뀌었다. ACTIVE 가 아니게 되면 authn 은 세션·토큰·API 키를 회수하고,
 * RETIRED 면 authz 는 남은 역할 할당을 모두 회수한다
 */
data class SubjectStatusChangedEvent(val subjectId: Long, val status: SubjectStatus)
