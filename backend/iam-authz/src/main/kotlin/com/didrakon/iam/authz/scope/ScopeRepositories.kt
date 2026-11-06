package com.didrakon.iam.authz.scope

import org.springframework.data.jpa.repository.JpaRepository

interface ScopeRepository : JpaRepository<Scope, Long> {
    fun findByScopeCode(scopeCode: String): Scope?
}

interface DataScopeRepository : JpaRepository<DataScope, Long> {
    fun findByScopeId(scopeId: Long): List<DataScope>
}
