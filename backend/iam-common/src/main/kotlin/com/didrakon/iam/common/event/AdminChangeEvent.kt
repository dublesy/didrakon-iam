package com.didrakon.iam.common.event

/**
 * 관리 화면에서 기준 데이터를 고치거나 켜고 끈 일. 감사 모듈이 받아 전후 값과 함께 기록한다.
 * [target] 은 감사 기록의 resource_type (예: ROLE, ORGANIZATION), [action] 은 UPDATE·ACTIVATE·DEACTIVATE·REMOVE 등.
 * [targetSubjectId] 는 바뀐 대상이 사람에게 딸린 것일 때(예: API 키의 소유자) 그 사람. 대상이 USER 면 비워도 [targetId] 를 쓴다
 */
data class AdminChangeEvent(
    val target: String,
    val targetId: Long,
    val action: String,
    val before: Map<String, Any?>?,
    val after: Map<String, Any?>?,
    val targetSubjectId: Long? = null,
)
