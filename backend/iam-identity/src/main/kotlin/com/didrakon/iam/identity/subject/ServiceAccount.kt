package com.didrakon.iam.identity.subject

import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.Table
import java.time.Instant

/** 시스템 간 호출용 계정. 설명은 상위 [Subject.description] 을 쓴다 */
@Entity
@Table(name = "service_account")
@DiscriminatorValue("SERVICE")
@PrimaryKeyJoinColumn(name = "subject_id")
class ServiceAccount(
    serviceName: String,
    ownerSubjectId: Long,
    environment: Environment,
    description: String? = null,
) : Subject(subjectName = serviceName, description = description) {
    override val subjectType: SubjectType get() = SubjectType.SERVICE

    @Column(name = "service_name", nullable = false, length = 200)
    var serviceName: String = serviceName
        protected set

    /** 책임자. 다른 애그리거트라 ID 로만 참조한다 */
    @Column(name = "owner_subject_id", nullable = false)
    var ownerSubjectId: Long = ownerSubjectId
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "environment", nullable = false, length = 30)
    var environment: Environment = environment
        protected set

    @Column(name = "last_used_at")
    var lastUsedAt: Instant? = null
        protected set
}
