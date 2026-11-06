package com.didrakon.iam.identity.subject

import com.didrakon.iam.common.jpa.BaseTimeEntity
import com.didrakon.iam.common.jpa.IdEntity
import com.didrakon.iam.common.jpa.idEquals
import com.didrakon.iam.common.jpa.idHashCode
import jakarta.persistence.Column
import jakarta.persistence.DiscriminatorColumn
import jakarta.persistence.DiscriminatorType
import jakarta.persistence.Entity
import jakarta.persistence.EnumType
import jakarta.persistence.Enumerated
import jakarta.persistence.GeneratedValue
import jakarta.persistence.GenerationType
import jakarta.persistence.Id
import jakarta.persistence.Inheritance
import jakarta.persistence.InheritanceType
import jakarta.persistence.Table

/** 권한을 받는 주체. 사람(User)뿐 아니라 서비스 계정, AI 에이전트, 애플리케이션도 같은 ID 체계를 쓴다 */
@Entity
@Table(name = "subject")
@Inheritance(strategy = InheritanceType.JOINED)
@DiscriminatorColumn(name = "subject_type", discriminatorType = DiscriminatorType.STRING, length = 30)
abstract class Subject(
    subjectName: String,
    description: String? = null,
) : BaseTimeEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "subject_id")
    override val id: Long? = null

    /** subject_type 컬럼은 Hibernate 가 판별 값으로 채운다 */
    abstract val subjectType: SubjectType

    @Column(name = "subject_name", nullable = false, length = 200)
    var subjectName: String = subjectName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: SubjectStatus = SubjectStatus.ACTIVE
        protected set

    @Column(name = "description", length = 1000)
    var description: String? = description
        protected set

    /** 화면에서 다루는 상태는 ACTIVE·DISABLED 뿐이다. LOCKED·RETIRED 는 각각 잠금·퇴직 처리가 정한다 */
    internal fun changeStatus(status: SubjectStatus) {
        this.status = status
    }

    internal fun rename(subjectName: String) {
        this.subjectName = subjectName
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

/** 판별 값은 [Subject] 하위 클래스의 @DiscriminatorValue 와 같아야 한다 */
enum class SubjectType { USER, SERVICE, AI_AGENT, APPLICATION }

enum class SubjectStatus { ACTIVE, LOCKED, DISABLED, RETIRED }

enum class Environment { DEV, STG, PROD }
