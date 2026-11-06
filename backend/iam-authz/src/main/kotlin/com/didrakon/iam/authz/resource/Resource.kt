package com.didrakon.iam.authz.resource

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

/** 권한을 거는 대상. SSO 클라이언트(시스템)마다 메뉴·API·데이터 등을 트리로 가진다 */
@Entity
@Table(name = "resource")
class Resource(
    clientId: Long,
    resourceKey: String,
    resourceName: String,
    resourceType: ResourceType,
    sensitivity: Sensitivity,
    parentResourceId: Long? = null,
    resourcePath: String? = null,
) : BaseCreatedEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "resource_id")
    override val id: Long? = null

    /** SSO_CLIENT.client_id (authn). ID 로만 참조한다 */
    @Column(name = "client_id", nullable = false, updatable = false)
    val clientId: Long = clientId

    @Column(name = "parent_resource_id")
    var parentResourceId: Long? = parentResourceId
        protected set

    /** 클라이언트 안에서 고유한 키 */
    @Column(name = "resource_key", nullable = false, length = 200, updatable = false)
    val resourceKey: String = resourceKey

    @Column(name = "resource_name", nullable = false, length = 200)
    var resourceName: String = resourceName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "resource_type", nullable = false, length = 30)
    var resourceType: ResourceType = resourceType
        protected set

    @Column(name = "resource_path", length = 1000)
    var resourcePath: String? = resourcePath
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "sensitivity", nullable = false, length = 30)
    var sensitivity: Sensitivity = sensitivity
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    fun deactivate() {
        isActive = false
    }

    internal fun update(resourceName: String, resourceType: ResourceType, resourcePath: String?, sensitivity: Sensitivity) {
        this.resourceName = resourceName
        this.resourceType = resourceType
        this.resourcePath = resourcePath
        this.sensitivity = sensitivity
    }

    internal fun activate() {
        isActive = true
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class ResourceType { SYSTEM, MENU, API, DATA, BUTTON, DOCUMENT }

enum class Sensitivity { PUBLIC, INTERNAL, CONFIDENTIAL, SECRET }
