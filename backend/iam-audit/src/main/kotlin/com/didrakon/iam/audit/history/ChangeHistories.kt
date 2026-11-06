package com.didrakon.iam.audit.history

import com.didrakon.iam.authz.assignment.RoleChangeType
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
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant

/** 역할 할당 변경 이력. 쓰기만 하고 고치지 않는다 */
@Entity
@Table(name = "role_change_history")
class RoleChangeHistory(
    roleId: Long,
    subjectId: Long,
    changeType: RoleChangeType,
    assignmentId: Long?,
    changedBy: Long?,
    reason: String?,
    changedAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "history_id")
    override val id: Long? = null

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Enumerated(EnumType.STRING)
    @Column(name = "change_type", nullable = false, length = 30, updatable = false)
    val changeType: RoleChangeType = changeType

    @Column(name = "assignment_id", updatable = false)
    val assignmentId: Long? = assignmentId

    /** null 이면 시스템 처리 */
    @Column(name = "changed_by", updatable = false)
    val changedBy: Long? = changedBy

    @Column(name = "reason", length = 1000, updatable = false)
    val reason: String? = reason

    @Column(name = "changed_at", nullable = false, updatable = false)
    val changedAt: Instant = changedAt

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 정책 ACTIVE 버전 변경 이력. old·new value 는 그 버전의 규칙 스냅샷(JSON) */
@Entity
@Table(name = "policy_change_history")
class PolicyChangeHistory(
    policyId: Long,
    oldVersion: Int?,
    newVersion: Int?,
    changedBy: Long?,
    changeReason: String?,
    oldValue: String?,
    newValue: String?,
    changedAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "history_id")
    override val id: Long? = null

    @Column(name = "policy_id", nullable = false, updatable = false)
    val policyId: Long = policyId

    @Column(name = "old_version", updatable = false)
    val oldVersion: Int? = oldVersion

    @Column(name = "new_version", updatable = false)
    val newVersion: Int? = newVersion

    @Column(name = "changed_by", updatable = false)
    val changedBy: Long? = changedBy

    @Column(name = "change_reason", length = 1000, updatable = false)
    val changeReason: String? = changeReason

    @Column(name = "old_value", columnDefinition = "json", updatable = false)
    val oldValue: String? = oldValue

    @Column(name = "new_value", columnDefinition = "json", updatable = false)
    val newValue: String? = newValue

    @Column(name = "changed_at", nullable = false, updatable = false)
    val changedAt: Instant = changedAt

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

interface RoleChangeHistoryRepository : JpaRepository<RoleChangeHistory, Long> {
    fun findBySubjectIdOrderByChangedAtDescIdDesc(subjectId: Long): List<RoleChangeHistory>
}

interface PolicyChangeHistoryRepository : JpaRepository<PolicyChangeHistory, Long> {
    fun findByPolicyIdOrderByChangedAtDescIdDesc(policyId: Long): List<PolicyChangeHistory>
}
