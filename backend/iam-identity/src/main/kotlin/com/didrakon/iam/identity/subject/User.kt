package com.didrakon.iam.identity.subject

import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorValue
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.PrimaryKeyJoinColumn
import jakarta.persistence.Table
import java.time.Instant
import java.time.LocalDate

/**
 * 사람 사용자. 임직원([UserKind.EMPLOYEE])은 사번으로, 외부 사용자([UserKind.EXTERNAL], 예: B2B 고객사 사용자)는 이메일로 식별한다.
 * 직위·직급은 소속마다 다르므로 [com.didrakon.iam.identity.organization.SubjectOrganization] 에 둔다
 */
@Entity
@Table(name = "user")
@DiscriminatorValue("USER")
@PrimaryKeyJoinColumn(name = "subject_id")
class User(
    empNo: String?,
    name: String,
    email: String? = null,
    phone: String? = null,
    hireDate: LocalDate? = null,
    userKind: UserKind = UserKind.EMPLOYEE,
) : Subject(subjectName = name) {
    override val subjectType: SubjectType get() = SubjectType.USER

    @Enumerated(EnumType.STRING)
    @Column(name = "user_kind", nullable = false, length = 30, updatable = false)
    val userKind: UserKind = userKind

    /** 그룹 전체에서 고유한 사번. 외부 사용자는 없다 */
    @Column(name = "emp_no", length = 50, updatable = false)
    val empNo: String? = empNo

    @Column(name = "name", nullable = false, length = 200)
    var name: String = name
        protected set

    @Column(name = "email")
    var email: String? = email
        protected set

    @Column(name = "phone", length = 30)
    var phone: String? = phone
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "employment_status", nullable = false, length = 30)
    var employmentStatus: EmploymentStatus = EmploymentStatus.EMPLOYED
        protected set

    /** 그룹 최초 입사일 */
    @Column(name = "hire_date")
    var hireDate: LocalDate? = hireDate
        protected set

    @Column(name = "retire_date")
    var retireDate: LocalDate? = null
        protected set

    @Column(name = "last_login_at")
    var lastLoginAt: Instant? = null
        protected set

    /** 퇴사 예정일만 정해 둔다. 상태는 그날 [retire] 될 때 바뀐다. null 이면 예약 취소 */
    internal fun scheduleRetire(retireDate: LocalDate?) {
        this.retireDate = retireDate
    }

    /** 휴직·복직 (인사 연동). 퇴직은 [retire] 로만 바꾼다 */
    internal fun changeEmployment(status: EmploymentStatus) {
        employmentStatus = status
    }

    internal fun retire(retireDate: LocalDate) {
        employmentStatus = EmploymentStatus.RETIRED
        this.retireDate = retireDate
        changeStatus(SubjectStatus.RETIRED)
    }

    internal fun updateProfile(name: String, email: String?, phone: String?, hireDate: LocalDate?) {
        this.name = name
        this.email = email
        this.phone = phone
        this.hireDate = hireDate
        rename(name)
    }
}

enum class EmploymentStatus { EMPLOYED, LEAVE, RETIRED }

/** 사용자 구분. EXTERNAL 은 인사 연동 대상이 아니다 */
enum class UserKind { EMPLOYEE, EXTERNAL }
