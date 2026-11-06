package com.didrakon.iam.identity.provider

import com.didrakon.iam.common.jpa.BaseCreatedEntity
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

/** 로그인 수단 제공자. LOCAL 은 자체 비밀번호, 나머지는 외부 IdP 연동 */
@Entity
@Table(name = "identity_provider")
class IdentityProvider(
    providerCode: String,
    providerName: String,
    providerType: ProviderType,
    issuer: String? = null,
    metadataUrl: String? = null,
) : BaseCreatedEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "provider_id")
    override val id: Long? = null

    @Column(name = "provider_code", nullable = false, length = 100, updatable = false)
    val providerCode: String = providerCode

    @Column(name = "provider_name", nullable = false, length = 200)
    var providerName: String = providerName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "provider_type", nullable = false, length = 30, updatable = false)
    val providerType: ProviderType = providerType

    @Column(name = "issuer", length = 1000)
    var issuer: String? = issuer
        protected set

    @Column(name = "metadata_url", length = 1000)
    var metadataUrl: String? = metadataUrl
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class ProviderType { LOCAL, OIDC, SAML, LDAP, AD }
