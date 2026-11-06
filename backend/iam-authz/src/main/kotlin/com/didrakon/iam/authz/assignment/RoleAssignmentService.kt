package com.didrakon.iam.authz.assignment

import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.subject.SubjectRepository
import org.springframework.beans.factory.ObjectProvider
import org.springframework.context.ApplicationEventPublisher
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock
import java.time.Instant

/** 역할 할당의 생성·회수는 모두 여기를 거친다. 변경마다 [RoleAssignmentChangedEvent] 를 발행한다 (감사 기록용) */
@Service
@Transactional
class RoleAssignmentService(
    private val assignmentRepository: RoleAssignmentRepository,
    private val roleRepository: RoleRepository,
    private val scopeRepository: ScopeRepository,
    private val subjectRepository: SubjectRepository,
    private val eventPublisher: ApplicationEventPublisher,
    private val grantGuards: ObjectProvider<RoleGrantGuard>,
    private val clock: Clock,
) {
    /** 직접 부여. scope 를 지정하지 않으면 GLOBAL */
    fun assignDirect(
        subjectId: Long,
        roleId: Long,
        scopeId: Long? = null,
        validUntil: Instant? = null,
        assignedBy: Long? = null,
        reason: String? = null,
    ): RoleAssignment {
        val resolvedScopeId = scopeId ?: globalScopeId()
        val duplicated = assignmentRepository.findActiveBySource(subjectId, AssignmentSourceType.DIRECT)
            .any { it.roleId == roleId && it.scopeId == resolvedScopeId }
        if (duplicated) throw BusinessRuleException("이미 같은 역할·scope 로 직접 할당되어 있습니다: subjectId=$subjectId, roleId=$roleId")
        return grant(subjectId, roleId, resolvedScopeId, AssignmentSourceType.DIRECT, null, validUntil, assignedBy, reason)
    }

    /** 직접 부여만 여기서 회수한다. 조직·그룹 할당은 규칙이나 소속을 바꾸면 따라서 회수된다 */
    fun revoke(assignmentId: Long, revokedBy: Long? = null, reason: String? = null) {
        val assignment = assignmentRepository.findByIdOrNull(assignmentId) ?: throw NotFoundException("역할 할당", assignmentId)
        if (assignment.sourceType != AssignmentSourceType.DIRECT) {
            throw BusinessRuleException("${assignment.sourceType} 할당은 출처 규칙을 바꿔 회수합니다: $assignmentId")
        }
        revokeAssignment(assignment, revokedBy, reason)
    }

    /**
     * 직접 할당의 종료 시각을 바꾼다 (null 이면 기한 없음). 지금 유효한 직접 할당만 바꾸고, 종료 시각은 지금 이후여야 한다
     * (바로 끝내려면 [revoke]). 이력은 MODIFY 로 남기고 사유에 이전·새 종료 시각을 적는다
     */
    fun changeValidUntil(assignmentId: Long, validUntil: Instant?, changedBy: Long?, reason: String?): RoleAssignment {
        val assignment = assignmentRepository.findByIdOrNull(assignmentId) ?: throw NotFoundException("역할 할당", assignmentId)
        if (assignment.sourceType != AssignmentSourceType.DIRECT) {
            throw BusinessRuleException("${assignment.sourceType} 할당의 기간은 출처 절차에서 정합니다: $assignmentId")
        }
        val now = clock.instant()
        if (!assignment.isEffectiveAt(now)) throw BusinessRuleException("지금 유효한 할당만 기간을 바꿀 수 있습니다: $assignmentId")
        if (validUntil != null && !validUntil.isAfter(now)) throw BusinessRuleException("종료 시각은 지금 이후여야 합니다. 바로 끝내려면 회수하세요")
        val change = "종료 시각 변경: ${assignment.validUntil ?: "없음"} → ${validUntil ?: "없음"}"
        assignment.changeValidUntil(validUntil)
        publish(assignment, RoleChangeType.MODIFY, changedBy, reason?.takeIf { it.isNotBlank() }?.let { "$change ($it)" } ?: change)
        return assignment
    }

    /**
     * 다른 모듈의 절차(JIT 승인, 위임, Break-glass)가 만든 할당. 출처 행이 있어야 하며 유효 기간을 지정할 수 있다.
     * 조직·그룹 할당은 동기화가, 직접 할당은 [assignDirect] 가 만든다.
     */
    fun grantForSource(
        subjectId: Long,
        roleId: Long,
        scopeId: Long,
        sourceType: AssignmentSourceType,
        sourceId: Long,
        validFrom: Instant,
        validUntil: Instant,
        assignedBy: Long?,
        reason: String?,
    ): RoleAssignment {
        if (sourceType !in PROCEDURE_SOURCES) throw BusinessRuleException("$sourceType 할당은 이 경로로 만들 수 없습니다")
        if (!validUntil.isAfter(validFrom)) throw BusinessRuleException("종료 시각은 시작 시각보다 뒤여야 합니다")
        return grant(subjectId, roleId, scopeId, sourceType, sourceId, validUntil, assignedBy, reason, validFrom)
    }

    /** [grantForSource] 로 만든 할당을 출처 단위로 회수한다 */
    fun revokeForSource(sourceType: AssignmentSourceType, sourceId: Long, revokedBy: Long?, reason: String?) {
        if (sourceType !in PROCEDURE_SOURCES) throw BusinessRuleException("$sourceType 할당은 이 경로로 회수할 수 없습니다")
        assignmentRepository.findActiveBySourceId(sourceType, sourceId).forEach { revokeAssignment(it, revokedBy, reason) }
    }

    /** 유효 기간이 끝난 ACTIVE 할당을 EXPIRED 로 바꾼다. 판정은 기간으로 이미 걸러내므로 상태와 이력을 맞추는 작업이다 */
    fun expireDue(): Int {
        val now = clock.instant()
        val due = assignmentRepository.findExpiredButActive(now)
        due.forEach {
            it.expire()
            publish(it, RoleChangeType.EXPIRE, null, "유효 기간 종료")
        }
        return due.size
    }

    internal fun grant(
        subjectId: Long,
        roleId: Long,
        scopeId: Long,
        sourceType: AssignmentSourceType,
        sourceId: Long?,
        validUntil: Instant?,
        assignedBy: Long?,
        reason: String?,
        // 기본값에서 필드를 읽으면 프록시(빈 필드)에서 계산되므로 null 로 받아 안에서 정한다
        validFrom: Instant? = null,
    ): RoleAssignment {
        if (!subjectRepository.existsById(subjectId)) throw NotFoundException("subject", subjectId)
        val role = roleRepository.findByIdOrNull(roleId) ?: throw NotFoundException("역할", roleId)
        if (!role.isActive) throw BusinessRuleException("비활성 역할은 부여할 수 없습니다: ${role.roleCode}")
        if (!scopeRepository.existsById(scopeId)) throw NotFoundException("scope", scopeId)
        val request = GrantRequest(subjectId, roleId, scopeId, sourceType, validFrom, validUntil)
        grantGuards.orderedStream().forEach { it.check(request) }

        val assignment = assignmentRepository.save(
            RoleAssignment(subjectId, roleId, scopeId, sourceType, sourceId, validFrom ?: clock.instant(), validUntil, assignedBy, reason),
        )
        publish(assignment, RoleChangeType.ASSIGN, assignedBy, reason)
        return assignment
    }

    internal fun revokeAssignment(assignment: RoleAssignment, revokedBy: Long?, reason: String?) {
        assignment.revoke(clock.instant(), revokedBy)
        publish(assignment, RoleChangeType.REVOKE, revokedBy, reason)
    }

    internal fun requireReview(assignment: RoleAssignment, reason: String) {
        assignment.requireReview()
        publish(assignment, RoleChangeType.REVIEW, null, reason)
    }

    /**
     * 담당자가 재검토(접근 재검토 캠페인 등)에서 유지를 확인했다. 재검토 표시가 있으면 지우고 이력(REVIEW)을 남긴다.
     * 표시가 없으면 바꿀 것이 없으므로 아무것도 하지 않는다
     */
    fun completeReview(assignmentId: Long, reviewedBy: Long?, reason: String) {
        val assignment = assignmentRepository.findByIdOrNull(assignmentId) ?: throw NotFoundException("역할 할당", assignmentId)
        if (!assignment.reviewRequired) return
        assignment.completeReview()
        publish(assignment, RoleChangeType.REVIEW, reviewedBy, reason)
    }

    /** 퇴사: 출처와 관계없이 지금 유효한 할당을 모두 회수한다 */
    fun revokeAllFor(subjectId: Long, reason: String) {
        assignmentRepository.findEffective(subjectId, clock.instant()).forEach { revokeAssignment(it, null, reason) }
    }

    /** 부여 시 scope 를 지정하지 않으면 쓰는 GLOBAL scope ID */
    fun globalScope(): Long = globalScopeId()

    /** subject 에게 지금 효력이 있는 할당 */
    @Transactional(readOnly = true)
    fun effectiveAssignments(subjectId: Long): List<RoleAssignment> = assignmentRepository.findEffective(subjectId, clock.instant())

    internal fun globalScopeId(): Long =
        scopeRepository.findByScopeCode(Scope.GLOBAL_CODE)?.requireId()
            ?: throw IllegalStateException("GLOBAL scope 행이 없습니다 (V3 마이그레이션 확인)")

    private fun publish(assignment: RoleAssignment, changeType: RoleChangeType, changedBy: Long?, reason: String?) {
        eventPublisher.publishEvent(
            RoleAssignmentChangedEvent(
                assignmentId = assignment.requireId(),
                subjectId = assignment.subjectId,
                roleId = assignment.roleId,
                scopeId = assignment.scopeId,
                sourceType = assignment.sourceType,
                changeType = changeType,
                changedBy = changedBy,
                reason = reason,
            ),
        )
    }
}

/** ROLE_CHANGE_HISTORY 의 change_type 과 같다. EXPIRE 는 유효 기간 종료 */
enum class RoleChangeType { ASSIGN, REVOKE, MODIFY, REVIEW, EXPIRE }

private val PROCEDURE_SOURCES = setOf(AssignmentSourceType.JIT, AssignmentSourceType.DELEGATION, AssignmentSourceType.BREAK_GLASS)

/** 부여하려는 할당. [validFrom] 이 null 이면 지금부터, [validUntil] 이 null 이면 기한 없음 */
data class GrantRequest(
    val subjectId: Long,
    val roleId: Long,
    val scopeId: Long,
    val sourceType: AssignmentSourceType,
    val validFrom: Instant? = null,
    val validUntil: Instant? = null,
)

/**
 * 할당 생성 직전 검사. 위반이면 예외를 던져 부여(와 그 부여를 일으킨 변경 전체)를 취소한다.
 * authz 는 governance 를 모르므로 직무 분리 등은 이 인터페이스를 구현해 끼운다.
 */
fun interface RoleGrantGuard {
    fun check(request: GrantRequest)
}

/** 역할 할당이 바뀌었다. audit 모듈이 ROLE_CHANGE_HISTORY·AUDIT_EVENT 로 남긴다. changedBy 가 null 이면 시스템 처리 */
data class RoleAssignmentChangedEvent(
    val assignmentId: Long,
    val subjectId: Long,
    val roleId: Long,
    val scopeId: Long,
    val sourceType: AssignmentSourceType,
    val changeType: RoleChangeType,
    val changedBy: Long?,
    val reason: String?,
)
