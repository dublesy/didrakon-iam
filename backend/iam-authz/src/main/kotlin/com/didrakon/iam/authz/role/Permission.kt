package com.didrakon.iam.authz.role

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
import java.time.Instant

/** 리소스 하나에 대한 행위 하나. effect=DENY 권한이 매칭되면 다른 허용보다 우선한다 (deny-overrides) */
@Entity
@Table(name = "permission")
class Permission(
    permissionCode: String,
    permissionName: String,
    resourceId: Long,
    action: PermissionAction,
    effect: PermissionEffect = PermissionEffect.ALLOW,
    isSensitive: Boolean = false,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "permission_id")
    override val id: Long? = null

    @Column(name = "permission_code", nullable = false, length = 100, updatable = false)
    val permissionCode: String = permissionCode

    @Column(name = "permission_name", nullable = false, length = 200)
    var permissionName: String = permissionName
        protected set

    @Column(name = "resource_id", nullable = false, updatable = false)
    val resourceId: Long = resourceId

    @Enumerated(EnumType.STRING)
    @Column(name = "action", nullable = false, length = 30, updatable = false)
    val action: PermissionAction = action

    @Enumerated(EnumType.STRING)
    @Column(name = "effect", nullable = false, length = 30)
    var effect: PermissionEffect = effect
        protected set

    @Column(name = "is_sensitive", nullable = false)
    var isSensitive: Boolean = isSensitive
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun rename(permissionName: String) {
        this.permissionName = permissionName
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class PermissionAction { READ, CREATE, UPDATE, DELETE, EXECUTE, APPROVE, EXPORT }

enum class PermissionEffect { ALLOW, DENY }

/** 역할에 담긴 권한. 같은 권한을 scope 만 다르게 여러 번 담을 수 있다 */
@Entity
@Table(name = "role_permission")
class RolePermission(
    roleId: Long,
    permissionId: Long,
    scopeId: Long,
    validFrom: Instant,
    validUntil: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "role_permission_id")
    override val id: Long? = null

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "permission_id", nullable = false, updatable = false)
    val permissionId: Long = permissionId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Column(name = "valid_from", nullable = false)
    var validFrom: Instant = validFrom
        protected set

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    /** 역할에서 권한을 뺀다. 이력이 남도록 지우지 않고 유효 기간을 끝낸다 */
    internal fun end(now: Instant) {
        validUntil = now
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}
