package com.didrakon.iam.identity.group

import jakarta.persistence.Column
import jakarta.persistence.Embeddable
import jakarta.persistence.EmbeddedId
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.Table
import org.hibernate.Hibernate
import java.io.Serializable
import java.time.Instant

/** 그룹 구성원. 연결 데이터라 탈퇴 시 hard delete 하고 이력은 감사 이벤트로 남긴다 */
@Entity
@Table(name = "group_member")
class GroupMember(
    groupId: Long,
    subjectId: Long,
    sourceType: GroupMemberSourceType,
    validFrom: Instant,
) {
    @EmbeddedId
    val id: GroupMemberId = GroupMemberId(groupId, subjectId)

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 30)
    var sourceType: GroupMemberSourceType = sourceType
        protected set

    @Column(name = "valid_from", nullable = false)
    var validFrom: Instant = validFrom
        protected set

    @Column(name = "valid_until")
    var validUntil: Instant? = null
        protected set

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other !is GroupMember || Hibernate.getClass(this) != Hibernate.getClass(other)) return false
        return id == other.id
    }

    override fun hashCode(): Int = id.hashCode()
}

@Embeddable
data class GroupMemberId(
    @Column(name = "group_id")
    val groupId: Long,
    @Column(name = "subject_id")
    val subjectId: Long,
) : Serializable

/** MANUAL = 직접 추가, RULE = DYNAMIC 그룹 규칙, SYNC = 외부 시스템 동기화 */
enum class GroupMemberSourceType { MANUAL, RULE, SYNC }
