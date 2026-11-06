package com.didrakon.iam.authz.assignment

import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import java.time.Instant

/**
 * 조직 구성원에게 역할을 주는 규칙. 판정은 이 규칙을 직접 읽지 않고,
 * [OrganizationRoleSync] 가 구성원마다 만든 ROLE_ASSIGNMENT(source_type=ORGANIZATION) 행을 쓴다.
 */
@Entity
@Table(name = "organization_role")
class OrganizationRole(
    orgId: Long,
    roleId: Long,
    scopeId: Long,
    applyToDescendants: Boolean,
    validFrom: Instant,
    validUntil: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "org_role_id")
    override val id: Long? = null

    @Column(name = "org_id", nullable = false, updatable = false)
    val orgId: Long = orgId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    /** 생성될 ROLE_ASSIGNMENT 의 scope */
    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    /** 하위 조직 구성원에게도 부여 */
    @Column(name = "apply_to_descendants", nullable = false, updatable = false)
    val applyToDescendants: Boolean = applyToDescendants

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    fun isEffectiveAt(now: Instant): Boolean = isActive && !validFrom.isAfter(now) && (validUntil?.isAfter(now) ?: true)

    internal fun deactivate() {
        isActive = false
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 그룹 구성원에게 역할을 주는 규칙. [GroupRoleSync] 가 ROLE_ASSIGNMENT(source_type=GROUP) 행으로 만든다 */
@Entity
@Table(name = "group_role")
class GroupRole(
    groupId: Long,
    roleId: Long,
    scopeId: Long,
    validFrom: Instant,
    validUntil: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "group_role_id")
    override val id: Long? = null

    @Column(name = "group_id", nullable = false, updatable = false)
    val groupId: Long = groupId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    /** 생성될 ROLE_ASSIGNMENT 의 scope */
    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    fun isEffectiveAt(now: Instant): Boolean = !validFrom.isAfter(now) && (validUntil?.isAfter(now) ?: true)

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}
