package com.didrakon.iam.identity.group

import com.didrakon.iam.common.jpa.BaseTimeEntity
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table

/** 조직과 무관하게 묶는 subject 집합. GROUP 은 MySQL 예약어라 테이블명은 user_group */
@Entity
@Table(name = "user_group")
class UserGroup(
    groupCode: String,
    groupName: String,
    groupType: GroupType,
    ruleExpression: String? = null,
) : BaseTimeEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "group_id")
    override val id: Long? = null

    @Column(name = "group_code", nullable = false, length = 100, updatable = false)
    val groupCode: String = groupCode

    @Column(name = "group_name", nullable = false, length = 200)
    var groupName: String = groupName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "group_type", nullable = false, length = 30)
    var groupType: GroupType = groupType
        protected set

    /** DYNAMIC 그룹의 구성원 규칙 (JSON 문자열) */
    @Column(name = "rule_expression", columnDefinition = "json")
    var ruleExpression: String? = ruleExpression
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun update(groupName: String, ruleExpression: String?) {
        this.groupName = groupName
        this.ruleExpression = ruleExpression
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** STATIC = 직접 지정, DYNAMIC = 규칙으로 계산 */
enum class GroupType { STATIC, DYNAMIC }
