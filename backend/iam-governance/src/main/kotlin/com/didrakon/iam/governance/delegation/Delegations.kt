package com.didrakon.iam.governance.delegation

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.RoleAssignmentChangedEvent
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.assignment.RoleChangeType
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import com.didrakon.iam.governance.event.DelegationAction
import com.didrakon.iam.governance.event.DelegationEvent
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.context.ApplicationEventPublisher
import org.springframework.context.event.EventListener
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 역할 단위 위임 (ERD 결정 사항 1). 위임 기간 동안 대리인에게 ROLE_ASSIGNMENT(source_type=DELEGATION)가 생긴다 */
@Entity
@Table(name = "delegation")
class Delegation(
    delegatorId: Long,
    delegateId: Long,
    roleId: Long,
    scopeId: Long,
    startTime: Instant,
    endTime: Instant,
    reason: String,
    status: DelegationStatus,
    createdAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "delegation_id")
    override val id: Long? = null

    @Column(name = "delegator_id", nullable = false, updatable = false)
    val delegatorId: Long = delegatorId

    @Column(name = "delegate_id", nullable = false, updatable = false)
    val delegateId: Long = delegateId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Column(name = "start_time", nullable = false, updatable = false)
    val startTime: Instant = startTime

    @Column(name = "end_time", nullable = false, updatable = false)
    val endTime: Instant = endTime

    @Column(name = "reason", nullable = false, length = 1000, updatable = false)
    val reason: String = reason

    /** PENDING(시작 전) → ACTIVE → EXPIRED. 할당 자체가 기간을 가지므로 판정에는 영향이 없고 표시용이다 */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: DelegationStatus = status
        protected set

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = createdAt

    fun isOpen(): Boolean = status == DelegationStatus.PENDING || status == DelegationStatus.ACTIVE

    internal fun revoke() {
        if (!isOpen()) throw BusinessRuleException("이미 끝난 위임입니다: $id ($status)")
        status = DelegationStatus.REVOKED
    }

    /** 시각에 맞게 PENDING·ACTIVE·EXPIRED 를 맞춘다. 바뀌었으면 true */
    internal fun refresh(now: Instant): Boolean {
        val next = when {
            !isOpen() -> status
            !endTime.isAfter(now) -> DelegationStatus.EXPIRED
            !startTime.isAfter(now) -> DelegationStatus.ACTIVE
            else -> DelegationStatus.PENDING
        }
        return (next != status).also { status = next }
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class DelegationStatus { PENDING, ACTIVE, EXPIRED, REVOKED }

interface DelegationRepository : JpaRepository<Delegation, Long> {
    fun findByDelegatorIdAndRoleId(delegatorId: Long, roleId: Long): List<Delegation>

    fun findByStatusIn(statuses: Collection<DelegationStatus>): List<Delegation>

    fun findTop200ByOrderByCreatedAtDesc(): List<Delegation>

    fun findByDelegatorIdOrDelegateIdOrderByCreatedAtDesc(delegatorId: Long, delegateId: Long): List<Delegation>
}

@Service
@Transactional
class DelegationService(
    private val delegationRepository: DelegationRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val assignmentService: RoleAssignmentService,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /**
     * 위임자가 직접 가진(위임받지 않은) 유효한 같은 역할·scope 할당이 있어야 한다. 재위임은 막는다.
     * 직무 분리 검사는 할당 생성 시 함께 적용된다.
     */
    fun delegate(
        delegatorId: Long,
        delegateId: Long,
        roleId: Long,
        scopeId: Long,
        startTime: Instant,
        endTime: Instant,
        reason: String,
    ): Delegation {
        val now = clock.instant()
        if (delegatorId == delegateId) throw BusinessRuleException("자기 자신에게는 위임할 수 없습니다")
        if (reason.isBlank()) throw BusinessRuleException("위임 사유가 필요합니다")
        if (!endTime.isAfter(startTime) || !endTime.isAfter(now)) throw BusinessRuleException("위임 기간이 올바르지 않습니다")
        val holds = assignmentRepository.findEffective(delegatorId, now).any {
            it.roleId == roleId && it.scopeId == scopeId && it.sourceType != AssignmentSourceType.DELEGATION
        }
        if (!holds) throw BusinessRuleException("위임자가 가진 역할·scope 만 위임할 수 있습니다 (위임받은 권한은 다시 위임할 수 없습니다)")

        val status = if (startTime.isAfter(now)) DelegationStatus.PENDING else DelegationStatus.ACTIVE
        val delegation = delegationRepository.save(Delegation(delegatorId, delegateId, roleId, scopeId, startTime, endTime, reason, status, now))
        assignmentService.grantForSource(
            delegateId, roleId, scopeId, AssignmentSourceType.DELEGATION, delegation.requireId(), startTime, endTime, delegatorId, reason,
        )
        publish(delegation, DelegationAction.CREATE, delegatorId, reason)
        return delegation
    }

    fun revoke(delegationId: Long, revokedBy: Long?, reason: String?) {
        val delegation = delegationRepository.findByIdOrNull(delegationId) ?: throw NotFoundException("위임", delegationId)
        delegation.revoke()
        assignmentService.revokeForSource(AssignmentSourceType.DELEGATION, delegationId, revokedBy, reason ?: "위임 회수")
        publish(delegation, DelegationAction.REVOKE, revokedBy, reason)
    }

    /** 위임자 본인만 자기 위임을 거둘 수 있다 */
    fun revokeAsDelegator(delegationId: Long, delegatorId: Long, reason: String?) {
        val delegation = delegationRepository.findByIdOrNull(delegationId) ?: throw NotFoundException("위임", delegationId)
        if (delegation.delegatorId != delegatorId) throw BusinessRuleException("본인이 한 위임만 거둘 수 있습니다")
        revoke(delegationId, delegatorId, reason)
    }

    /** 위임자가 그 역할을 잃으면(회수·만료) 그 역할로 한 위임도 끝낸다 */
    @EventListener
    fun onRoleAssignmentChanged(event: RoleAssignmentChangedEvent) {
        if (event.changeType != RoleChangeType.REVOKE && event.changeType != RoleChangeType.EXPIRE) return
        if (event.sourceType == AssignmentSourceType.DELEGATION) return
        val stillHolds = assignmentRepository.findEffective(event.subjectId, clock.instant()).any {
            it.roleId == event.roleId && it.scopeId == event.scopeId && it.sourceType != AssignmentSourceType.DELEGATION
        }
        if (stillHolds) return
        delegationRepository.findByDelegatorIdAndRoleId(event.subjectId, event.roleId)
            .filter { it.isOpen() && it.scopeId == event.scopeId }
            .forEach { revoke(it.requireId(), null, "위임자의 역할이 회수되어 위임 종료") }
    }

    /** 진행 중·시작 전 위임 전부와 최근 위임 200건 (만든 시각 역순) */
    @Transactional(readOnly = true)
    fun delegations(): List<Delegation> =
        (delegationRepository.findByStatusIn(listOf(DelegationStatus.PENDING, DelegationStatus.ACTIVE)) + delegationRepository.findTop200ByOrderByCreatedAtDesc())
            .distinctBy { it.id }.sortedByDescending { it.createdAt }

    /** 본인이 하거나 받은 위임 */
    @Transactional(readOnly = true)
    fun delegationsOf(subjectId: Long): List<Delegation> =
        delegationRepository.findByDelegatorIdOrDelegateIdOrderByCreatedAtDesc(subjectId, subjectId)

    /** 시작 시각이 된 위임은 ACTIVE, 끝난 위임은 EXPIRED 로 맞춘다 */
    fun refreshStatuses(): Int {
        val now = clock.instant()
        return delegationRepository.findByStatusIn(listOf(DelegationStatus.PENDING, DelegationStatus.ACTIVE)).count { it.refresh(now) }
    }

    private fun publish(delegation: Delegation, action: DelegationAction, actorId: Long?, reason: String?) {
        eventPublisher.publishEvent(
            DelegationEvent(delegation.requireId(), delegation.delegatorId, delegation.delegateId, delegation.roleId, action, actorId, reason),
        )
    }
}
