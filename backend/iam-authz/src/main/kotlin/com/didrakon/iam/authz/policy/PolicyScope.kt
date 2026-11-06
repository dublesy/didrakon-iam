package com.didrakon.iam.authz.policy

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

/** 정책이 적용되는 대상. 권한·리소스·역할 중 정확히 하나 (DB CHECK) */
@Entity
@Table(name = "policy_target")
class PolicyTarget private constructor(
    policyId: Long,
    permissionId: Long?,
    resourceId: Long?,
    roleId: Long?,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "policy_target_id")
    override val id: Long? = null

    @Column(name = "policy_id", nullable = false, updatable = false)
    val policyId: Long = policyId

    @Column(name = "permission_id", updatable = false)
    val permissionId: Long? = permissionId

    /** 이 리소스와 그 하위 리소스에 적용 */
    @Column(name = "resource_id", updatable = false)
    val resourceId: Long? = resourceId

    /** 이 역할로 허용된 요청에 적용 */
    @Column(name = "role_id", updatable = false)
    val roleId: Long? = roleId

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()

    companion object {
        fun permission(policyId: Long, permissionId: Long) = PolicyTarget(policyId, permissionId, null, null)

        fun resource(policyId: Long, resourceId: Long) = PolicyTarget(policyId, null, resourceId, null)

        fun role(policyId: Long, roleId: Long) = PolicyTarget(policyId, null, null, roleId)
    }
}

/**
 * deny-overrides 의 유일한 예외 수단. 지정한 subject·리소스(둘 중 하나 이상, DB CHECK)에 해당하면 정책을 건너뛴다.
 * 둘 다 지정하면 둘 다 맞아야 한다.
 */
@Entity
@Table(name = "policy_exception")
class PolicyException(
    policyId: Long,
    subjectId: Long?,
    resourceId: Long?,
    reason: String,
    validFrom: Instant,
    validUntil: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "exception_id")
    override val id: Long? = null

    @Column(name = "policy_id", nullable = false, updatable = false)
    val policyId: Long = policyId

    @Column(name = "subject_id", updatable = false)
    val subjectId: Long? = subjectId

    @Column(name = "resource_id", updatable = false)
    val resourceId: Long? = resourceId

    @Column(name = "reason", nullable = false, length = 1000, updatable = false)
    val reason: String = reason

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    fun covers(subjectId: Long, resourceId: Long, now: Instant): Boolean =
        (this.subjectId == null || this.subjectId == subjectId) &&
            (this.resourceId == null || this.resourceId == resourceId) &&
            !validFrom.isAfter(now) && (validUntil?.isAfter(now) ?: true)

    internal fun end(now: Instant) {
        validUntil = now
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}
