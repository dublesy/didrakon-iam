package com.didrakon.iam.identity.subject

import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.Table

@Entity
@Table(name = "application")
@DiscriminatorValue("APPLICATION")
@PrimaryKeyJoinColumn(name = "subject_id")
class Application(
    applicationName: String,
    applicationType: ApplicationType,
    ownerSubjectId: Long,
    environment: Environment,
) : Subject(subjectName = applicationName) {
    override val subjectType: SubjectType get() = SubjectType.APPLICATION

    @Column(name = "application_name", nullable = false, length = 200)
    var applicationName: String = applicationName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "application_type", nullable = false, length = 30)
    var applicationType: ApplicationType = applicationType
        protected set

    /** 책임자. 다른 애그리거트라 ID 로만 참조한다 */
    @Column(name = "owner_subject_id", nullable = false)
    var ownerSubjectId: Long = ownerSubjectId
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "environment", nullable = false, length = 30)
    var environment: Environment = environment
        protected set
}

enum class ApplicationType { WEB, MOBILE, API, BATCH }
