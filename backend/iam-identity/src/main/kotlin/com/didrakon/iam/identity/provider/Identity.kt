package com.didrakon.iam.identity.provider

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

/** 한 IdP 에서의 계정. 한 subject 가 여러 IdP 계정을 가질 수 있다 */
@Entity
@Table(name = "identity")
class Identity(
    subjectId: Long,
    providerId: Long,
    externalId: String,
    loginId: String? = null,
    email: String? = null,
    isPrimary: Boolean = false,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "identity_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Column(name = "provider_id", nullable = false, updatable = false)
    val providerId: Long = providerId

    /** IdP 쪽 고유 식별자. (provider_id, external_id) 가 유일하다 */
    @Column(name = "external_id", nullable = false, updatable = false)
    val externalId: String = externalId

    @Column(name = "login_id")
    var loginId: String? = loginId
        protected set

    @Column(name = "email")
    var email: String? = email
        protected set

    @Column(name = "is_primary", nullable = false)
    var isPrimary: Boolean = isPrimary
        protected set

    @Column(name = "is_verified", nullable = false)
    var isVerified: Boolean = false
        protected set

    @Column(name = "last_login_at")
    var lastLoginAt: Instant? = null
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}
