package com.didrakon.iam.common.jpa

import org.hibernate.Hibernate

/** BIGINT 대리 키를 가지는 엔티티 */
interface IdEntity {
    val id: Long?

    fun requireId(): Long = id ?: throw IllegalStateException("저장 전 엔티티는 ID 가 없습니다: ${javaClass.simpleName}")
}

/**
 * 프록시를 벗긴 클래스가 같고 ID 가 같으면 같은 엔티티로 본다.
 * 저장 전(ID 없음)에는 자기 자신과만 같다.
 */
fun IdEntity.idEquals(other: Any?): Boolean {
    if (this === other) return true
    if (other !is IdEntity || Hibernate.getClass(this) != Hibernate.getClass(other)) return false
    return id != null && id == other.id
}

/** 저장 전후로 값이 바뀌지 않도록 클래스 기준으로 계산한다 */
fun IdEntity.idHashCode(): Int = Hibernate.getClass(this).hashCode()
