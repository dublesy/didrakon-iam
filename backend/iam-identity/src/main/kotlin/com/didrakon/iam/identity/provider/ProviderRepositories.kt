package com.didrakon.iam.identity.provider

import org.springframework.data.jpa.repository.JpaRepository

interface IdentityProviderRepository : JpaRepository<IdentityProvider, Long> {
    fun findByProviderCode(providerCode: String): IdentityProvider?
}

interface IdentityRepository : JpaRepository<Identity, Long> {
    fun findByProviderIdAndExternalId(providerId: Long, externalId: String): Identity?

    fun findBySubjectId(subjectId: Long): List<Identity>
}
