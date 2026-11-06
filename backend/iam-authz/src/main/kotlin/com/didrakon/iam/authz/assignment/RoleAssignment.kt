package com.didrakon.iam.authz.assignment

import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.jpa.BaseCreatedEntity
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

/**
 * 권한 판정의 단일 경로. 직접 부여뿐 아니라 그룹·조직·JIT·위임·Break-glass 로 생긴 권한도 모두 이 행으로 만든다.
 * 출처는 (source_type, source_id) 로 남고, 회수는 삭제가 아니라 상태 변경이다.
 */
@Entity
@Table(name = "role_assignment")
class RoleAssignment(
    subjectId: Long,
    roleId: Long,
    scopeId: Long,
    sourceType: AssignmentSourceType,
    sourceId: Long?,
    validFrom: Instant,
    validUntil: Instant? = null,
    assignedBy: Long? = null,
    reason: String? = null,
) : BaseCreatedEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "assignment_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 30, updatable = false)
    val sourceType: AssignmentSourceType = sourceType

    /** 출처 행 ID (논리 참조). DIRECT, SYSTEM 은 null */
    @Column(name = "source_id", updatable = false)
    val sourceId: Long? = sourceId

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: AssignmentStatus = AssignmentStatus.ACTIVE
        protected set

    /** 전적 등으로 담당자 재검토가 필요하다 */
    @Column(name = "review_required", nullable = false)
    var reviewRequired: Boolean = false
        protected set

    @Column(name = "assigned_by", updatable = false)
    val assignedBy: Long? = assignedBy

    @Column(name = "reason", length = 1000, updatable = false)
    val reason: String? = reason

    @Column(name = "revoked_at")
    var revokedAt: Instant? = null
        protected set

    @Column(name = "revoked_by")
    var revokedBy: Long? = null
        protected set

    /** 상태가 ACTIVE 이고 [now] 가 유효 기간 안이면 판정에 쓴다. EXPIRED 갱신이 늦어도 기간으로 걸러진다 */
    fun isEffectiveAt(now: Instant): Boolean =
        status == AssignmentStatus.ACTIVE && !validFrom.isAfter(now) && (validUntil?.isAfter(now) ?: true)

    internal fun revoke(at: Instant, by: Long?) {
        if (status != AssignmentStatus.ACTIVE) throw BusinessRuleException("활성 상태가 아닌 할당은 회수할 수 없습니다: $id ($status)")
        status = AssignmentStatus.REVOKED
        revokedAt = at
        revokedBy = by
    }

    internal fun changeValidUntil(until: Instant?) {
        validUntil = until
    }

    internal fun expire() {
        status = AssignmentStatus.EXPIRED
    }

    internal fun requireReview() {
        reviewRequired = true
    }

    internal fun completeReview() {
        reviewRequired = false
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class AssignmentSourceType { DIRECT, GROUP, ORGANIZATION, JIT, DELEGATION, BREAK_GLASS, SYSTEM }

enum class AssignmentStatus { ACTIVE, EXPIRED, REVOKED }
