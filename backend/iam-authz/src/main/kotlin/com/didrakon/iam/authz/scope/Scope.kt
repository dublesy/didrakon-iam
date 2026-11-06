package com.didrakon.iam.authz.scope

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

/**
 * 역할·권한이 미치는 범위. 부여 시 scope 를 지정하지 않으면 [GLOBAL_CODE] 행을 쓴다.
 * ORGANIZATION 은 org_id, RESOURCE 는 resource_id 를 기준으로 하며 include_descendants 면 하위까지 포함한다.
 */
@Entity
@Table(name = "scope")
class Scope(
    scopeCode: String,
    scopeName: String,
    scopeType: ScopeType,
    orgId: Long? = null,
    resourceId: Long? = null,
    includeDescendants: Boolean = false,
    parentScopeId: Long? = null,
    scopeExpression: String? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "scope_id")
    override val id: Long? = null

    @Column(name = "scope_code", nullable = false, length = 100, updatable = false)
    val scopeCode: String = scopeCode

    @Column(name = "scope_name", nullable = false, length = 200)
    var scopeName: String = scopeName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "scope_type", nullable = false, length = 30, updatable = false)
    val scopeType: ScopeType = scopeType

    @Column(name = "org_id", updatable = false)
    val orgId: Long? = orgId

    @Column(name = "resource_id", updatable = false)
    val resourceId: Long? = resourceId

    @Column(name = "parent_scope_id")
    var parentScopeId: Long? = parentScopeId
        protected set

    /** PROJECT·DATA scope 의 조건 (JSON). RBAC 판정에서는 해석하지 않는다 */
    @Column(name = "scope_expression", columnDefinition = "json")
    var scopeExpression: String? = scopeExpression
        protected set

    @Column(name = "include_descendants", nullable = false)
    var includeDescendants: Boolean = includeDescendants
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun update(scopeName: String, includeDescendants: Boolean) {
        this.scopeName = scopeName
        this.includeDescendants = includeDescendants
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()

    companion object {
        /** V3 마이그레이션이 넣는 기본 scope */
        const val GLOBAL_CODE = "GLOBAL"
    }
}

enum class ScopeType { GLOBAL, ORGANIZATION, RESOURCE, PROJECT, DATA }
