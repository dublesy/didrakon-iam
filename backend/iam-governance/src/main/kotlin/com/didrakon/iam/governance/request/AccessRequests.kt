package com.didrakon.iam.governance.request

import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
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
import jakarta.persistence.LockModeType
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Lock
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant

/** 역할 단위 접근 요청 (ERD 결정 사항 1). JIT 와 승인이 필요한 Break-glass 가 같은 승인 절차를 쓴다 */
@Entity
@Table(name = "access_request")
class AccessRequest(
    requestType: AccessRequestType,
    subjectId: Long,
    roleId: Long,
    scopeId: Long,
    reason: String,
    riskLevel: RiskLevel,
    requestedStart: Instant,
    requestedEnd: Instant,
    createdAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "request_id")
    override val id: Long? = null

    @Enumerated(EnumType.STRING)
    @Column(name = "request_type", nullable = false, length = 30, updatable = false)
    val requestType: AccessRequestType = requestType

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Column(name = "reason", nullable = false, length = 1000, updatable = false)
    val reason: String = reason

    @Enumerated(EnumType.STRING)
    @Column(name = "risk_level", length = 30, updatable = false)
    val riskLevel: RiskLevel = riskLevel

    @Column(name = "requested_start", nullable = false, updatable = false)
    val requestedStart: Instant = requestedStart

    @Column(name = "requested_end", nullable = false, updatable = false)
    val requestedEnd: Instant = requestedEnd

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: AccessRequestStatus = AccessRequestStatus.PENDING
        protected set

    /** 처리가 끝난(승인·반려·취소·만료) 시각. 대기 중이면 비어 있다 */
    @Column(name = "closed_at")
    var closedAt: Instant? = null
        protected set

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = createdAt

    internal fun moveTo(next: AccessRequestStatus, at: Instant) {
        if (status != AccessRequestStatus.PENDING) throw BusinessRuleException("처리가 끝난 요청입니다: $id ($status)")
        status = next
        closedAt = at
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class AccessRequestType { JIT, BREAK_GLASS }

enum class AccessRequestStatus { PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED }

/**
 * 승인 조건. 요청 역할의 role_type 이 같은 정책을 먼저, 없으면 role_type 이 비어 있는 기본 정책을 쓴다.
 * 역할 단위 요청이라 resource_sensitivity 는 아직 쓰지 않는다.
 */
@Entity
@Table(name = "approval_policy")
class ApprovalPolicy(
    policyName: String,
    roleType: RoleType?,
    requiredApprovalCount: Int,
    requireSecurityTeam: Boolean = false,
    requireOwner: Boolean = false,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "approval_policy_id")
    override val id: Long? = null

    @Column(name = "policy_name", nullable = false, length = 200)
    var policyName: String = policyName
        protected set

    @Column(name = "resource_sensitivity", length = 30)
    var resourceSensitivity: String? = null
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "role_type", length = 30)
    var roleType: RoleType? = roleType
        protected set

    /** 서로 다른 승인자 수 */
    @Column(name = "required_approval_count", nullable = false)
    var requiredApprovalCount: Int = requiredApprovalCount
        protected set

    /** 보안팀(SECURITY_TEAM 그룹) 구성원 승인 1건 이상 */
    @Column(name = "require_security_team", nullable = false)
    var requireSecurityTeam: Boolean = requireSecurityTeam
        protected set

    /** 요청자 PRIMARY 소속 조직의 관리자(is_manager) 승인 1건 이상 */
    @Column(name = "require_owner", nullable = false)
    var requireOwner: Boolean = requireOwner
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 승인자 한 명의 결정 */
@Entity
@Table(name = "approval")
class Approval(
    requestId: Long,
    approverId: Long,
    approvalPolicyId: Long?,
    approvalStep: Int,
    status: ApprovalStatus,
    comment: String?,
    decidedAt: Instant,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "approval_id")
    override val id: Long? = null

    @Column(name = "request_id", nullable = false, updatable = false)
    val requestId: Long = requestId

    @Column(name = "approver_id", nullable = false, updatable = false)
    val approverId: Long = approverId

    @Column(name = "approval_policy_id", updatable = false)
    val approvalPolicyId: Long? = approvalPolicyId

    @Column(name = "approval_step", nullable = false, updatable = false)
    val approvalStep: Int = approvalStep

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30, updatable = false)
    val status: ApprovalStatus = status

    @Column(name = "comment", length = 1000, updatable = false)
    val comment: String? = comment

    @Column(name = "decided_at", updatable = false)
    val decidedAt: Instant = decidedAt

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class ApprovalStatus { PENDING, APPROVED, REJECTED, SKIPPED }

interface AccessRequestRepository : JpaRepository<AccessRequest, Long> {
    /** 승인·반려·취소가 동시에 들어와도 한 번에 하나만 처리하도록 요청 행을 잠근다 */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select r from AccessRequest r where r.id = :id")
    fun findByIdForUpdate(@Param("id") id: Long): AccessRequest?

    fun findBySubjectIdAndStatus(subjectId: Long, status: AccessRequestStatus): List<AccessRequest>

    fun findBySubjectIdAndRoleIdAndStatus(subjectId: Long, roleId: Long, status: AccessRequestStatus): List<AccessRequest>

    fun findByStatusOrderByCreatedAtAsc(status: AccessRequestStatus): List<AccessRequest>

    fun findTop200ByStatusNotOrderByCreatedAtDesc(status: AccessRequestStatus): List<AccessRequest>

    fun findBySubjectIdOrderByCreatedAtDesc(subjectId: Long): List<AccessRequest>

    @Query(
        """
        select r from AccessRequest r
        where r.status = com.didrakon.iam.governance.request.AccessRequestStatus.PENDING and r.requestedEnd <= :now
        """,
    )
    fun findPendingEndedBefore(@Param("now") now: Instant): List<AccessRequest>
}

interface ApprovalPolicyRepository : JpaRepository<ApprovalPolicy, Long> {
    fun findByIsActiveTrue(): List<ApprovalPolicy>
}

interface ApprovalRepository : JpaRepository<Approval, Long> {
    fun findByRequestIdOrderByApprovalStepAsc(requestId: Long): List<Approval>

    fun findByRequestIdIn(requestIds: Collection<Long>): List<Approval>
}
