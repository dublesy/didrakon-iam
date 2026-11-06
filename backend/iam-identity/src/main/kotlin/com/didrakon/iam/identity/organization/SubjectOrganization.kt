package com.didrakon.iam.identity.organization

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
import jakarta.persistence.Table
import java.time.Instant

/**
 * subject 의 조직 소속. 직위·직급은 소속마다 다르다.
 * valid_until 이 NULL 이면 현재 소속이며, 활성 PRIMARY 소속은 subject 당 1개다 (DB UNIQUE + [MembershipService]).
 */
@Entity
@Table(name = "subject_organization")
class SubjectOrganization(
    subjectId: Long,
    orgId: Long,
    membershipType: MembershipType,
    validFrom: Instant,
    jobTitle: String? = null,
    jobGrade: String? = null,
    isManager: Boolean = false,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "membership_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "org_id", nullable = false, updatable = false)
    val orgId: Long = orgId

    @Enumerated(EnumType.STRING)
    @Column(name = "membership_type", nullable = false, length = 30, updatable = false)
    val membershipType: MembershipType = membershipType

    @Column(name = "job_title", length = 100)
    var jobTitle: String? = jobTitle
        protected set

    @Column(name = "job_grade", length = 100)
    var jobGrade: String? = jobGrade
        protected set

    @Column(name = "is_manager", nullable = false)
    var isManager: Boolean = isManager
        protected set

    @Column(name = "valid_from", nullable = false, updatable = false)
    val validFrom: Instant = validFrom

    @Column(name = "valid_until")
    var validUntil: Instant? = null
        protected set

    internal fun updateJob(jobTitle: String?, jobGrade: String?, isManager: Boolean) {
        this.jobTitle = jobTitle
        this.jobGrade = jobGrade
        this.isManager = isManager
    }

    internal fun end(at: Instant) {
        if (validUntil != null) throw BusinessRuleException("이미 종료된 소속입니다: $id")
        validUntil = at
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** PRIMARY = 주 소속(법인 판별 기준), SECONDARY = 겸직, TEMPORARY = 파견 등 임시 소속 */
enum class MembershipType { PRIMARY, SECONDARY, TEMPORARY }
