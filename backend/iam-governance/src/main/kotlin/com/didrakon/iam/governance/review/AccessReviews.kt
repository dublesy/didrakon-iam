package com.didrakon.iam.governance.review

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.AttributeConverter
import jakarta.persistence.Column
import jakarta.persistence.Convert
import jakarta.persistence.Converter
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Table
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Duration
import java.time.Instant

enum class ReviewScopeType { ALL, ORGANIZATION, ROLE }

enum class AccessReviewDecision { PENDING, KEEP, REVOKE }

enum class AccessReviewStatus { OPEN, CLOSED }

/**
 * 접근 재검토 캠페인. 만들 때 대상 할당을 [AccessReviewItem] 으로 스냅샷하고, 검토자가 항목마다 유지·회수를 정한다.
 * 기한이 지나거나 마감하면 남은 항목에 [onOverdue] 를 적용하고 닫는다.
 * [escalationDays] 가 있으면 기한이 지났을 때 먼저 미결정 항목을 상위 조직 관리자에게 넘기고, 그 날수만큼 더 기다린 뒤([finalDueAt]) 닫는다.
 */
@Entity
@Table(name = "access_review_campaign")
class AccessReviewCampaign(
    name: String,
    scopeType: ReviewScopeType,
    scopeOrgId: Long?,
    scopeRoleId: Long?,
    includeDescendants: Boolean,
    privilegedOnly: Boolean,
    sources: Set<AssignmentSourceType>,
    dueAt: Instant,
    onOverdue: AccessReviewDecision,
    createdBy: Long?,
    createdAt: Instant,
    escalationDays: Int? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "campaign_id")
    override val id: Long? = null

    @Column(name = "name", nullable = false, length = 200, updatable = false)
    val name: String = name

    @Enumerated(EnumType.STRING)
    @Column(name = "scope_type", nullable = false, length = 20, updatable = false)
    val scopeType: ReviewScopeType = scopeType

    @Column(name = "scope_org_id", updatable = false)
    val scopeOrgId: Long? = scopeOrgId

    @Column(name = "scope_role_id", updatable = false)
    val scopeRoleId: Long? = scopeRoleId

    @Column(name = "include_descendants", nullable = false, updatable = false)
    val includeDescendants: Boolean = includeDescendants

    @Column(name = "privileged_only", nullable = false, updatable = false)
    val privilegedOnly: Boolean = privilegedOnly

    @Convert(converter = SourceTypesConverter::class)
    @Column(name = "sources", nullable = false, columnDefinition = "json", updatable = false)
    val sources: Set<AssignmentSourceType> = sources

    @Column(name = "due_at", nullable = false, updatable = false)
    val dueAt: Instant = dueAt

    @Enumerated(EnumType.STRING)
    @Column(name = "on_overdue", nullable = false, length = 20, updatable = false)
    val onOverdue: AccessReviewDecision = onOverdue

    @Column(name = "escalation_days", updatable = false)
    val escalationDays: Int? = escalationDays

    @Column(name = "escalated_at")
    var escalatedAt: Instant? = null
        protected set

    /** 이관까지 마친 뒤 닫는 시각. 이관이 없으면 [dueAt] */
    val finalDueAt: Instant get() = escalationDays?.let { dueAt.plus(Duration.ofDays(it.toLong())) } ?: dueAt

    /** 지금 검토자가 지켜야 할 기한: 이관했으면 [finalDueAt], 아니면 [dueAt] */
    val currentDueAt: Instant get() = if (escalatedAt != null) finalDueAt else dueAt

    /** 기한이 지났고 이관할 차례인지 */
    fun needsEscalationAt(now: Instant): Boolean = escalationDays != null && escalatedAt == null && !dueAt.isAfter(now)

    /** 기한 경과로 닫을 차례인지. 이관하는 캠페인은 이관을 먼저 한다 */
    fun closableAt(now: Instant): Boolean = !needsEscalationAt(now) && !finalDueAt.isAfter(now)

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 20)
    var status: AccessReviewStatus = AccessReviewStatus.OPEN
        protected set

    @Column(name = "created_by", updatable = false)
    val createdBy: Long? = createdBy

    @Column(name = "created_at", nullable = false, updatable = false)
    val createdAt: Instant = createdAt

    @Column(name = "closed_at")
    var closedAt: Instant? = null
        protected set

    internal fun requireOpen() {
        if (status != AccessReviewStatus.OPEN) throw BusinessRuleException("이미 닫힌 접근 재검토입니다: $id")
    }

    internal fun markEscalated(at: Instant) {
        requireOpen()
        escalatedAt = at
    }

    internal fun close(at: Instant) {
        requireOpen()
        status = AccessReviewStatus.CLOSED
        closedAt = at
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 검토할 할당 한 건. 이름·역할·범위는 캠페인을 만든 시점 값을 증적으로 남긴다 */
@Entity
@Table(name = "access_review_item")
class AccessReviewItem(
    campaignId: Long,
    assignmentId: Long,
    subjectId: Long,
    roleId: Long,
    scopeId: Long,
    sourceType: AssignmentSourceType,
    reviewerId: Long?,
    snapshot: ReviewSnapshot,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "item_id")
    override val id: Long? = null

    @Column(name = "campaign_id", nullable = false, updatable = false)
    val campaignId: Long = campaignId

    @Column(name = "assignment_id", nullable = false, updatable = false)
    val assignmentId: Long = assignmentId

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "role_id", nullable = false, updatable = false)
    val roleId: Long = roleId

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Enumerated(EnumType.STRING)
    @Column(name = "source_type", nullable = false, length = 30, updatable = false)
    val sourceType: AssignmentSourceType = sourceType

    /** 검토자. 기한 경과로 상위 조직 관리자에게 넘기면 바뀐다 */
    @Column(name = "reviewer_id")
    var reviewerId: Long? = reviewerId
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "decision", nullable = false, length = 20)
    var decision: AccessReviewDecision = AccessReviewDecision.PENDING
        protected set

    @Column(name = "decided_by")
    var decidedBy: Long? = null
        protected set

    @Column(name = "decided_at")
    var decidedAt: Instant? = null
        protected set

    @Column(name = "comment", length = 1000)
    var comment: String? = null
        protected set

    @Column(name = "subject_name", nullable = false, length = 200, updatable = false)
    val subjectName: String = snapshot.subjectName

    @Column(name = "emp_no", length = 50, updatable = false)
    val empNo: String? = snapshot.empNo

    @Column(name = "org_name", length = 200, updatable = false)
    val orgName: String? = snapshot.orgName

    @Column(name = "role_code", nullable = false, length = 100, updatable = false)
    val roleCode: String = snapshot.roleCode

    @Column(name = "role_name", nullable = false, length = 200, updatable = false)
    val roleName: String = snapshot.roleName

    @Column(name = "is_privileged", nullable = false, updatable = false)
    val isPrivileged: Boolean = snapshot.isPrivileged

    @Column(name = "scope_name", nullable = false, length = 200, updatable = false)
    val scopeName: String = snapshot.scopeName

    @Column(name = "reviewer_name", length = 200)
    var reviewerName: String? = snapshot.reviewerName
        protected set

    @Column(name = "escalated_from_id")
    var escalatedFromId: Long? = null
        protected set

    @Column(name = "escalated_from_name", length = 200)
    var escalatedFromName: String? = null
        protected set

    @Column(name = "escalated_at")
    var escalatedAt: Instant? = null
        protected set

    @Column(name = "assignment_valid_from", nullable = false, updatable = false)
    val assignmentValidFrom: Instant = snapshot.validFrom

    @Column(name = "assignment_valid_until", updatable = false)
    val assignmentValidUntil: Instant? = snapshot.validUntil

    @Column(name = "review_required", nullable = false, updatable = false)
    val reviewRequired: Boolean = snapshot.reviewRequired

    /** 상위 조직 관리자에게 넘긴다. 원래 검토자는 증적으로 남긴다 */
    internal fun escalateTo(newReviewerId: Long, newReviewerName: String?, at: Instant) {
        if (decision != AccessReviewDecision.PENDING) throw BusinessRuleException("이미 결정된 검토 항목입니다: $id ($decision)")
        escalatedFromId = reviewerId
        escalatedFromName = reviewerName
        reviewerId = newReviewerId
        reviewerName = newReviewerName
        escalatedAt = at
    }

    internal fun decide(decision: AccessReviewDecision, by: Long?, at: Instant, comment: String?) {
        if (this.decision != AccessReviewDecision.PENDING) throw BusinessRuleException("이미 결정된 검토 항목입니다: $id (${this.decision})")
        this.decision = decision
        decidedBy = by
        decidedAt = at
        this.comment = comment
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 항목에 함께 저장하는 생성 시점 값 */
data class ReviewSnapshot(
    val subjectName: String,
    val empNo: String?,
    val orgName: String?,
    val roleCode: String,
    val roleName: String,
    val isPrivileged: Boolean,
    val scopeName: String,
    val reviewerName: String?,
    val validFrom: Instant,
    val validUntil: Instant?,
    val reviewRequired: Boolean,
)

/** 출처 집합 ↔ JSON 문자열 배열. 값이 enum 이름뿐이라 직접 만든다 */
@Converter
class SourceTypesConverter : AttributeConverter<Set<AssignmentSourceType>, String> {
    override fun convertToDatabaseColumn(attribute: Set<AssignmentSourceType>?): String =
        attribute.orEmpty().sortedBy { it.ordinal }.joinToString(",", "[", "]") { "\"${it.name}\"" }

    override fun convertToEntityAttribute(dbData: String?): Set<AssignmentSourceType> =
        dbData.orEmpty().trim().removePrefix("[").removeSuffix("]").split(",")
            .map { it.trim().removeSurrounding("\"") }
            .filter { it.isNotEmpty() }
            .map { AssignmentSourceType.valueOf(it) }
            .toSet()
}

/** 캠페인별 결정 수 */
class ReviewDecisionCount(val campaignId: Long, val decision: AccessReviewDecision, val count: Long)

interface AccessReviewCampaignRepository : JpaRepository<AccessReviewCampaign, Long> {
    fun findAllByOrderByIdDesc(): List<AccessReviewCampaign>

    fun findByStatusAndDueAtLessThanEqual(status: AccessReviewStatus, dueAt: Instant): List<AccessReviewCampaign>
}

interface AccessReviewItemRepository : JpaRepository<AccessReviewItem, Long> {
    fun findByCampaignIdOrderById(campaignId: Long): List<AccessReviewItem>

    fun findByCampaignIdAndDecisionOrderById(campaignId: Long, decision: AccessReviewDecision): List<AccessReviewItem>

    fun findByReviewerIdAndDecisionOrderById(reviewerId: Long, decision: AccessReviewDecision): List<AccessReviewItem>

    @Query(
        """
        select new com.didrakon.iam.governance.review.ReviewDecisionCount(i.campaignId, i.decision, count(i))
        from AccessReviewItem i where i.campaignId in :campaignIds group by i.campaignId, i.decision
        """,
    )
    fun countByDecision(@Param("campaignIds") campaignIds: Collection<Long>): List<ReviewDecisionCount>
}
