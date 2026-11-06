package com.didrakon.iam.authn.apikey

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
import org.springframework.data.jpa.repository.JpaRepository
import java.time.Instant

/** 서비스 계정의 자격 증명(인증서·개인키 등). 비밀값은 보관소에 두고 참조만 저장한다 */
@Entity
@Table(name = "service_credential")
class ServiceCredential(
    subjectId: Long,
    credentialType: ServiceCredentialType,
    secretReference: String,
    issuedAt: Instant,
    expireAt: Instant? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "credential_id")
    override val id: Long? = null

    @Column(name = "subject_id", nullable = false, updatable = false)
    val subjectId: Long = subjectId

    @Enumerated(EnumType.STRING)
    @Column(name = "credential_type", nullable = false, length = 30, updatable = false)
    val credentialType: ServiceCredentialType = credentialType

    @Column(name = "secret_reference", nullable = false, length = 500, updatable = false)
    val secretReference: String = secretReference

    @Column(name = "issued_at", nullable = false, updatable = false)
    val issuedAt: Instant = issuedAt

    @Column(name = "expire_at")
    var expireAt: Instant? = expireAt
        protected set

    @Column(name = "revoked", nullable = false)
    var revoked: Boolean = false
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class ServiceCredentialType { CLIENT_SECRET, CERTIFICATE, PRIVATE_KEY }

interface ServiceCredentialRepository : JpaRepository<ServiceCredential, Long>
