package com.didrakon.iam.authz.resource

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

/** ReBAC 관계 종류. 리소스 간 관계와 subject 관계가 함께 쓴다 */
@Entity
@Table(name = "relation_type")
class RelationType(
    relationCode: String,
    relationName: String,
    description: String? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "relation_type_id")
    override val id: Long? = null

    /** OWNS, MANAGES, APPROVES, BELONGS_TO, MEMBER_OF, ASSIGNED_TO 등 */
    @Column(name = "relation_code", nullable = false, length = 100, updatable = false)
    val relationCode: String = relationCode

    @Column(name = "relation_name", nullable = false, length = 200)
    var relationName: String = relationName
        protected set

    @Column(name = "description", length = 1000)
    var description: String? = description
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

@Entity
@Table(name = "resource_relation")
class ResourceRelation(
    sourceResourceId: Long,
    relationTypeId: Long,
    targetResourceId: Long,
    validFrom: Instant,
    validUntil: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "resource_relation_id")
    override val id: Long? = null

    @Column(name = "source_resource_id", nullable = false, updatable = false)
    val sourceResourceId: Long = sourceResourceId

    @Column(name = "relation_type_id", nullable = false, updatable = false)
    val relationTypeId: Long = relationTypeId

    @Column(name = "target_resource_id", nullable = false, updatable = false)
    val targetResourceId: Long = targetResourceId

    @Column(name = "valid_from", nullable = false)
    var validFrom: Instant = validFrom
        protected set

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** subject 가 다른 subject 나 리소스와 맺는 관계 (예: 홍길동 OWNS 문서 A). 대상은 둘 중 하나만 (DB CHECK) */
@Entity
@Table(name = "subject_relation")
class SubjectRelation private constructor(
    subjectId: Long,
    relationTypeId: Long,
    targetSubjectId: Long?,
    targetResourceId: Long?,
    validFrom: Instant,
    validUntil: Instant?,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subject_relation_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "relation_type_id", nullable = false, updatable = false)
    val relationTypeId: Long = relationTypeId

    @Column(name = "target_subject_id", updatable = false)
    val targetSubjectId: Long? = targetSubjectId

    @Column(name = "target_resource_id", updatable = false)
    val targetResourceId: Long? = targetResourceId

    @Column(name = "valid_from", nullable = false)
    var validFrom: Instant = validFrom
        protected set

    @Column(name = "valid_until")
    var validUntil: Instant? = validUntil
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()

    companion object {
        fun toSubject(subjectId: Long, relationTypeId: Long, targetSubjectId: Long, validFrom: Instant, validUntil: Instant? = null) =
            SubjectRelation(subjectId, relationTypeId, targetSubjectId, null, validFrom, validUntil)

        fun toResource(subjectId: Long, relationTypeId: Long, targetResourceId: Long, validFrom: Instant, validUntil: Instant? = null) =
            SubjectRelation(subjectId, relationTypeId, null, targetResourceId, validFrom, validUntil)
    }
}
