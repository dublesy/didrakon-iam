package com.didrakon.iam.governance.sod

import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.GrantRequest
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.assignment.RoleGrantGuard
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import com.didrakon.iam.identity.subject.SubjectRepository
import jakarta.persistence.Column
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.findByIdOrNull
import org.springframework.data.repository.query.Param
import org.springframework.stereotype.Component
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 함께 가질 수 없는 역할 쌍. (A,B)와 (B,A) 중복을 막기 위해 항상 작은 ID 를 a 에 둔다 (DB CHECK) */
@Entity
@Table(name = "role_conflict")
class RoleConflict private constructor(
    roleIdA: Long,
    roleIdB: Long,
    severity: RiskLevel,
    description: String?,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "conflict_id")
    override val id: Long? = null

    @Column(name = "role_id_a", nullable = false, updatable = false)
    val roleIdA: Long = roleIdA

    @Column(name = "role_id_b", nullable = false, updatable = false)
    val roleIdB: Long = roleIdB

    @Column(name = "conflict_type", nullable = false, length = 30, updatable = false)
    val conflictType: String = "MUTUAL_EXCLUSION"

    @Enumerated(EnumType.STRING)
    @Column(name = "severity", nullable = false, length = 30)
    var severity: RiskLevel = severity
        protected set

    @Column(name = "description", length = 1000)
    var description: String? = description
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    fun otherRole(roleId: Long): Long = if (roleId == roleIdA) roleIdB else roleIdA

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    internal fun update(severity: RiskLevel, description: String?) {
        this.severity = severity
        this.description = description
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()

    companion object {
        fun of(roleId1: Long, roleId2: Long, severity: RiskLevel, description: String? = null): RoleConflict {
            if (roleId1 == roleId2) throw BusinessRuleException("같은 역할끼리는 충돌을 정의할 수 없습니다")
            return RoleConflict(minOf(roleId1, roleId2), maxOf(roleId1, roleId2), severity, description)
        }
    }
}

/** 승인된 직무 분리 예외. 기간 안에서만 충돌 역할을 함께 가질 수 있다 */
@Entity
@Table(name = "role_conflict_exception")
class RoleConflictException(
    conflictId: Long,
    subjectId: Long,
    approvedBy: Long,
    reason: String,
    validFrom: Instant,
    validUntil: Instant?,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "exception_id")
    override val id: Long? = null

    @Column(name = "conflict_id", nullable = false, updatable = false)
    val conflictId: Long = conflictId

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "approved_by", nullable = false, updatable = false)
    val approvedBy: Long = approvedBy

    @Column(name = "reason", nullable = false, length = 1000, updatable = false)
    val reason: String = reason

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    fun isEffectiveAt(now: Instant): Boolean = isActive && !validFrom.isAfter(now) && (validUntil?.isAfter(now) ?: true)

    /** [from]~[until] 기간 전체를 덮는가. 기한 없는 할당은 기한 없는 예외만 덮는다 (예외가 끝난 뒤까지 충돌 역할이 남지 않게) */
    fun covers(from: Instant, until: Instant?): Boolean {
        if (!isActive || validFrom.isAfter(from)) return false
        val end = validUntil ?: return true
        return until != null && !until.isAfter(end) && end.isAfter(from)
    }

    internal fun end(now: Instant) {
        validUntil = now
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

interface RoleConflictRepository : JpaRepository<RoleConflict, Long> {
    @Query("select c from RoleConflict c where c.isActive = true and (c.roleIdA = :roleId or c.roleIdB = :roleId)")
    fun findActiveInvolving(@Param("roleId") roleId: Long): List<RoleConflict>

    fun findByRoleIdAAndRoleIdB(roleIdA: Long, roleIdB: Long): RoleConflict?
}

interface RoleConflictExceptionRepository : JpaRepository<RoleConflictException, Long> {
    fun findByConflictIdAndSubjectId(conflictId: Long, subjectId: Long): List<RoleConflictException>

    fun findByConflictId(conflictId: Long): List<RoleConflictException>
}

/**
 * 직무 분리(SoD) 검사. authz 의 모든 부여 경로(직접·조직·그룹·JIT·위임)에 끼워져, 충돌 역할을 이미 가진 subject 에게
 * 부여하면 거부한다. 승인된 예외가 있으면 허용한다. 비상 접근(BREAK_GLASS)은 막지 않고 감사 기록으로 남긴다.
 */
@Component
class SodGuard(
    private val conflictRepository: RoleConflictRepository,
    private val exceptionRepository: RoleConflictExceptionRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val roleRepository: RoleRepository,
    private val clock: Clock,
) : RoleGrantGuard {
    override fun check(request: GrantRequest) {
        if (request.sourceType == AssignmentSourceType.BREAK_GLASS) return
        violation(request.subjectId, request.roleId, request.validFrom, request.validUntil)?.let { conflictingRoleId ->
            val codes = roleRepository.findAllById(listOf(request.roleId, conflictingRoleId)).associate { it.requireId() to it.roleCode }
            throw BusinessRuleException(
                "직무 분리 위반: ${codes[request.roleId]} 역할은 ${codes[conflictingRoleId]} 역할과 함께 가질 수 없습니다 " +
                    "(승인된 예외가 있으면 예외 기간 안으로 종료 시각을 정하세요)",
            )
        }
    }

    /**
     * [from]~[until] 기간에 [roleId] 를 주면 부딪히는 충돌 역할 ID. 없으면 null.
     * 지금 가진 역할뿐 아니라 곧 받을 역할(시작 전인 위임·JIT)도 기간이 겹치면 센다. 빼고 보면 두 역할을 미래 시작으로 따로 받아 함께 가질 수 있다.
     * 예외는 이 기간 전체를 덮을 때만 인정한다
     */
    fun violation(subjectId: Long, roleId: Long, from: Instant? = null, until: Instant? = null): Long? {
        val now = clock.instant()
        val start = maxOf(from ?: now, now)
        val conflicts = conflictRepository.findActiveInvolving(roleId)
        if (conflicts.isEmpty()) return null
        val heldRoles = assignmentRepository.findCurrentOrUpcoming(subjectId, now)
            .filter { it.validFrom.isBefore(until ?: Instant.MAX) && start.isBefore(it.validUntil ?: Instant.MAX) }
            .map { it.roleId }.toSet()
        return conflicts.firstOrNull { conflict ->
            conflict.otherRole(roleId) in heldRoles &&
                exceptionRepository.findByConflictIdAndSubjectId(conflict.requireId(), subjectId).none { it.covers(start, until) }
        }?.otherRole(roleId)
    }
}

@Service
@Transactional
class RoleConflictService(
    private val conflictRepository: RoleConflictRepository,
    private val exceptionRepository: RoleConflictExceptionRepository,
    private val assignmentRepository: RoleAssignmentRepository,
    private val assignmentService: RoleAssignmentService,
    private val roleRepository: RoleRepository,
    private val subjectRepository: SubjectRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    /** 끈 규칙은 부여를 막지 않는다 */
    fun changeActive(conflictId: Long, active: Boolean): RoleConflict {
        val conflict = find(conflictId)
        if (conflict.isActive == active) return conflict
        val before = mapOf("isActive" to conflict.isActive)
        conflict.changeActive(active)
        eventPublisher.publishEvent(AdminChangeEvent("ROLE_CONFLICT", conflictId, if (active) "ACTIVATE" else "DEACTIVATE", before, mapOf("isActive" to active)))
        return conflict
    }

    /** 심각도·설명만 바꾼다. 역할 쌍은 바꾸지 않는다 (다른 쌍이면 새 규칙을 만들고 이 규칙을 끈다) */
    fun update(conflictId: Long, severity: RiskLevel, description: String?): RoleConflict {
        val conflict = find(conflictId)
        val before = snapshot(conflict)
        conflict.update(severity, description?.trim()?.ifBlank { null })
        val after = snapshot(conflict)
        if (before != after) eventPublisher.publishEvent(AdminChangeEvent("ROLE_CONFLICT", conflictId, "UPDATE", before, after))
        return conflict
    }

    private fun snapshot(c: RoleConflict) = mapOf("severity" to c.severity.name, "description" to c.description)

    /**
     * 예외를 지금 끝낸다. 이력이 남도록 지우지 않는다.
     * 예외 덕에 받은 충돌 역할(예외가 시작된 뒤 직접 받은 것 중 가장 나중 것)도 회수한다. 예외 기간으로 종료 시각을 묶어 받았더라도
     * 예외를 일찍 끝내면 그 시각까지 두 역할이 남기 때문이다. JIT·위임은 예외 기간 안에서만 받을 수 있어 그 기간에 끝난다
     */
    fun endException(exceptionId: Long) {
        val exception = exceptionRepository.findByIdOrNull(exceptionId) ?: throw NotFoundException("직무 분리 예외", exceptionId)
        val now = clock.instant()
        if (exception.validUntil?.isAfter(now) == false) return
        exception.end(now)
        eventPublisher.publishEvent(
            AdminChangeEvent("ROLE_CONFLICT", exception.conflictId, "END_EXCEPTION", mapOf("exceptionId" to exceptionId, "subjectId" to exception.subjectId), null),
        )
        revokeGrantedUnder(exception, now)
    }

    private fun revokeGrantedUnder(exception: RoleConflictException, now: Instant) {
        val conflict = conflictRepository.findByIdOrNull(exception.conflictId) ?: return
        val pair = setOf(conflict.roleIdA, conflict.roleIdB)
        val held = assignmentRepository.findCurrentOrUpcoming(exception.subjectId, now).filter { it.roleId in pair }
        if (held.map { it.roleId }.toSet() != pair) return
        held.filter { it.sourceType == AssignmentSourceType.DIRECT && !it.validFrom.isBefore(exception.validFrom) }
            .maxByOrNull { it.requireId() }
            ?.let { assignmentService.revoke(it.requireId(), null, "직무 분리 예외 종료") }
    }

    /** 이미 두 역할을 함께 가진 subject 는 그대로 둔다 (정의 이후의 부여부터 막는다) */
    fun define(roleId1: Long, roleId2: Long, severity: RiskLevel, description: String? = null): RoleConflict {
        listOf(roleId1, roleId2).forEach { if (!roleRepository.existsById(it)) throw NotFoundException("역할", it) }
        val conflict = RoleConflict.of(roleId1, roleId2, severity, description)
        if (conflictRepository.findByRoleIdAAndRoleIdB(conflict.roleIdA, conflict.roleIdB) != null) {
            throw BusinessRuleException("이미 정의된 역할 충돌입니다")
        }
        val saved = conflictRepository.save(conflict)
        eventPublisher.publishEvent(
            AdminChangeEvent("ROLE_CONFLICT", saved.requireId(), "CREATE", null, mapOf("roleIdA" to saved.roleIdA, "roleIdB" to saved.roleIdB) + snapshot(saved)),
        )
        return saved
    }

    fun grantException(conflictId: Long, subjectId: Long, approvedBy: Long, reason: String, validUntil: Instant?): RoleConflictException {
        if (!conflictRepository.existsById(conflictId)) throw NotFoundException("역할 충돌", conflictId)
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        if (reason.isBlank()) throw BusinessRuleException("예외 사유가 필요합니다")
        if (approvedBy == subjectId) throw BusinessRuleException("본인의 직무 분리 예외는 승인할 수 없습니다")
        val exception = exceptionRepository.save(RoleConflictException(conflictId, subjectId, approvedBy, reason, clock.instant(), validUntil))
        // 예외는 그 사람에게 직무 분리를 끄는 것과 같으므로 기준 데이터 변경으로 남긴다
        eventPublisher.publishEvent(
            AdminChangeEvent(
                "ROLE_CONFLICT", conflictId, "ADD_EXCEPTION", null,
                mapOf("exceptionId" to exception.requireId(), "subjectId" to subjectId, "approvedBy" to approvedBy, "reason" to reason, "validUntil" to validUntil?.toString()),
            ),
        )
        return exception
    }

    @Transactional(readOnly = true)
    fun all(): List<RoleConflict> = conflictRepository.findAll().sortedBy { it.id }

    @Transactional(readOnly = true)
    fun exceptions(conflictId: Long): List<RoleConflictException> = exceptionRepository.findByConflictId(conflictId)

    @Transactional(readOnly = true)
    fun find(conflictId: Long): RoleConflict = conflictRepository.findByIdOrNull(conflictId) ?: throw NotFoundException("역할 충돌", conflictId)
}
