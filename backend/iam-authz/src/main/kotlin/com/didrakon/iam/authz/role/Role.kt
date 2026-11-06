package com.didrakon.iam.authz.role

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

@Entity
@Table(name = "role")
class Role(
    roleCode: String,
    roleName: String,
    roleType: RoleType,
    isSensitive: Boolean = false,
    isPrivileged: Boolean = false,
    priority: Int = 0,
) : BaseTimeEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_id")
    override val id: Long? = null

    @Column(name = "role_code", nullable = false, length = 100, updatable = false)
    val roleCode: String = roleCode

    @Column(name = "role_name", nullable = false, length = 200)
    var roleName: String = roleName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "role_type", nullable = false, length = 30)
    var roleType: RoleType = roleType
        protected set

    /** 표시 순서·설명용. 판정 로직은 이 값을 읽지 않는다 (ERD 결정 사항 4) */
    @Column(name = "priority", nullable = false)
    var priority: Int = priority
        protected set

    @Column(name = "is_sensitive", nullable = false)
    var isSensitive: Boolean = isSensitive
        protected set

    @Column(name = "is_privileged", nullable = false)
    var isPrivileged: Boolean = isPrivileged
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    fun deactivate() {
        isActive = false
    }

    internal fun update(roleName: String, roleType: RoleType, priority: Int, isSensitive: Boolean, isPrivileged: Boolean) {
        this.roleName = roleName
        this.roleType = roleType
        this.priority = priority
        this.isSensitive = isSensitive
        this.isPrivileged = isPrivileged
    }

    internal fun activate() {
        isActive = true
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class RoleType { SYSTEM, BUSINESS, CUSTOM, PRIVILEGED }
