package com.didrakon.iam.authz.role

import org.springframework.context.ApplicationEventPublisher
import com.didrakon.iam.common.event.AdminChangeEvent
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.resource.Resource
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.organization.OrganizationRepository
import org.springframework.data.repository.findByIdOrNull
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import java.time.Clock

/** 역할에 담긴 권한 한 줄 (권한·scope 함께) */
data class RolePermissionView(val rolePermissionId: Long, val permission: Permission, val scope: Scope)

/** 리소스·역할·권한·scope 정의 (RBAC 카탈로그) */
@Service
@Transactional
class AuthzCatalogService(
    private val resourceRepository: ResourceRepository,
    private val roleRepository: RoleRepository,
    private val permissionRepository: PermissionRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val scopeRepository: ScopeRepository,
    private val organizationRepository: OrganizationRepository,
    private val assignmentService: RoleAssignmentService,
    private val eventPublisher: ApplicationEventPublisher,
    private val clock: Clock,
) {
    @Transactional(readOnly = true)
    fun roles(): List<Role> = roleRepository.findAll().sortedBy { it.roleCode }

    @Transactional(readOnly = true)
    fun role(roleId: Long): Role = roleRepository.findByIdOrNull(roleId) ?: throw NotFoundException("역할", roleId)

    @Transactional(readOnly = true)
    fun rolePermissions(roleId: Long): List<RolePermissionView> {
        val now = clock.instant()
        val rolePermissions = rolePermissionRepository.findByRoleId(roleId).filter { it.validUntil?.isAfter(now) ?: true }
        val permissions = permissionRepository.findAllById(rolePermissions.map { it.permissionId }).associateBy { it.requireId() }
        val scopes = scopeRepository.findAllById(rolePermissions.map { it.scopeId }).associateBy { it.requireId() }
        return rolePermissions.map { RolePermissionView(it.requireId(), permissions.getValue(it.permissionId), scopes.getValue(it.scopeId)) }
    }

    /** clientId 를 주면 그 클라이언트 것만 */
    @Transactional(readOnly = true)
    fun resources(clientId: Long?): List<Resource> =
        resourceRepository.findAll().filter { clientId == null || it.clientId == clientId }.sortedBy { it.resourceKey }

    @Transactional(readOnly = true)
    fun permissions(resourceId: Long?): List<Permission> =
        permissionRepository.findAll().filter { resourceId == null || it.resourceId == resourceId }.sortedBy { it.permissionCode }

    @Transactional(readOnly = true)
    fun scopes(): List<Scope> = scopeRepository.findAll().sortedBy { it.scopeCode }

    fun createResource(
        clientId: Long,
        resourceKey: String,
        resourceName: String,
        resourceType: ResourceType,
        sensitivity: Sensitivity,
        parentResourceId: Long? = null,
        resourcePath: String? = null,
    ): Resource {
        parentResourceId?.let {
            val parent = resourceRepository.findByIdOrNull(it) ?: throw NotFoundException("상위 리소스", it)
            if (parent.clientId != clientId) throw BusinessRuleException("상위 리소스는 같은 클라이언트에 있어야 합니다")
        }
        if (resourceRepository.findByClientIdAndResourceKey(clientId, resourceKey) != null) {
            throw BusinessRuleException("이미 있는 리소스 키입니다: $resourceKey")
        }
        return resourceRepository.save(Resource(clientId, resourceKey, resourceName, resourceType, sensitivity, parentResourceId, resourcePath))
    }

    fun createRole(roleCode: String, roleName: String, roleType: RoleType, isSensitive: Boolean, isPrivileged: Boolean, priority: Int): Role {
        if (roleRepository.findByRoleCode(roleCode) != null) throw BusinessRuleException("이미 있는 역할 코드입니다: $roleCode")
        return roleRepository.save(Role(roleCode, roleName, roleType, isSensitive, isPrivileged, priority))
    }

    /** 비활성 역할은 판정에서 빠진다. 기존 할당은 남지만 효력이 없다 */
    fun deactivateRole(roleId: Long) {
        changeRoleActive(roleId, false)
    }

    fun changeRoleActive(roleId: Long, active: Boolean): Role {
        val role = role(roleId)
        if (role.isActive == active) return role
        val before = role.snapshot()
        if (active) role.activate() else role.deactivate()
        changed("ROLE", roleId, if (active) "ACTIVATE" else "DEACTIVATE", before, role.snapshot())
        return role
    }

    /** 코드는 바꾸지 않는다 (다른 시스템·정책이 가리키는 키) */
    fun updateRole(roleId: Long, roleName: String, roleType: RoleType, priority: Int, isSensitive: Boolean, isPrivileged: Boolean): Role {
        val role = role(roleId)
        if (roleName.isBlank()) throw BusinessRuleException("역할 이름이 필요합니다")
        val before = role.snapshot()
        role.update(roleName.trim(), roleType, priority, isSensitive, isPrivileged)
        changed("ROLE", roleId, "UPDATE", before, role.snapshot())
        return role
    }

    /** 역할에서 권한을 뺀다. 이력이 남도록 지우지 않고 유효 기간을 끝낸다 */
    fun removeRolePermission(rolePermissionId: Long) {
        val rolePermission = rolePermissionRepository.findByIdOrNull(rolePermissionId) ?: throw NotFoundException("역할 권한", rolePermissionId)
        val now = clock.instant()
        if (rolePermission.validUntil?.isAfter(now) == false) return
        rolePermission.end(now)
        changed(
            "ROLE", rolePermission.roleId, "REMOVE_PERMISSION",
            mapOf("permissionId" to rolePermission.permissionId, "scopeId" to rolePermission.scopeId), null,
        )
    }

    fun updateResource(resourceId: Long, resourceName: String, resourceType: ResourceType, resourcePath: String?, sensitivity: Sensitivity): Resource {
        val resource = resource(resourceId)
        if (resourceName.isBlank()) throw BusinessRuleException("리소스 이름이 필요합니다")
        val before = resource.snapshot()
        resource.update(resourceName.trim(), resourceType, resourcePath?.trim()?.ifEmpty { null }, sensitivity)
        changed("RESOURCE", resourceId, "UPDATE", before, resource.snapshot())
        return resource
    }

    /** 끈 리소스는 판정에서 늘 거부된다 (하위 리소스는 각자 상태를 따른다) */
    fun changeResourceActive(resourceId: Long, active: Boolean): Resource {
        val resource = resource(resourceId)
        if (resource.isActive == active) return resource
        val before = resource.snapshot()
        if (active) resource.activate() else resource.deactivate()
        changed("RESOURCE", resourceId, if (active) "ACTIVATE" else "DEACTIVATE", before, resource.snapshot())
        return resource
    }

    /** 행위·효과는 바꾸지 않는다. 다르게 하려면 새 권한을 만든다 (역할에 담긴 의미가 몰래 바뀌지 않도록) */
    fun renamePermission(permissionId: Long, permissionName: String): Permission {
        val permission = permission(permissionId)
        if (permissionName.isBlank()) throw BusinessRuleException("권한 이름이 필요합니다")
        val before = permission.snapshot()
        permission.rename(permissionName.trim())
        changed("PERMISSION", permissionId, "UPDATE", before, permission.snapshot())
        return permission
    }

    fun changePermissionActive(permissionId: Long, active: Boolean): Permission {
        val permission = permission(permissionId)
        if (permission.isActive == active) return permission
        val before = permission.snapshot()
        permission.changeActive(active)
        changed("PERMISSION", permissionId, if (active) "ACTIVATE" else "DEACTIVATE", before, permission.snapshot())
        return permission
    }

    fun createPermission(
        permissionCode: String,
        permissionName: String,
        resourceId: Long,
        action: PermissionAction,
        effect: PermissionEffect,
    ): Permission {
        if (!resourceRepository.existsById(resourceId)) throw NotFoundException("리소스", resourceId)
        return permissionRepository.save(Permission(permissionCode, permissionName, resourceId, action, effect))
    }

    /** 역할에 권한을 담는다. scope 미지정은 GLOBAL */
    fun grantPermission(roleId: Long, permissionId: Long, scopeId: Long? = null): RolePermission {
        if (!roleRepository.existsById(roleId)) throw NotFoundException("역할", roleId)
        if (!permissionRepository.existsById(permissionId)) throw NotFoundException("권한", permissionId)
        val resolvedScopeId = scopeId ?: assignmentService.globalScope()
        if (!scopeRepository.existsById(resolvedScopeId)) throw NotFoundException("scope", resolvedScopeId)
        return rolePermissionRepository.save(RolePermission(roleId, permissionId, resolvedScopeId, clock.instant()))
    }

    /** ORGANIZATION 은 orgId, RESOURCE 는 resourceId 가 있어야 한다. GLOBAL 은 마이그레이션이 만든 1행만 둔다 */
    fun createScope(
        scopeCode: String,
        scopeName: String,
        scopeType: ScopeType,
        orgId: Long? = null,
        resourceId: Long? = null,
        includeDescendants: Boolean = false,
    ): Scope {
        when (scopeType) {
            ScopeType.GLOBAL -> throw BusinessRuleException("GLOBAL scope 는 하나만 둡니다")
            ScopeType.ORGANIZATION -> if (orgId == null || !organizationRepository.existsById(orgId)) throw BusinessRuleException("조직 scope 에는 존재하는 조직이 필요합니다")
            ScopeType.RESOURCE -> if (resourceId == null || !resourceRepository.existsById(resourceId)) throw BusinessRuleException("리소스 scope 에는 존재하는 리소스가 필요합니다")
            ScopeType.PROJECT, ScopeType.DATA -> Unit
        }
        if (scopeRepository.findByScopeCode(scopeCode) != null) throw BusinessRuleException("이미 있는 scope 코드입니다: $scopeCode")
        return scopeRepository.save(Scope(scopeCode, scopeName, scopeType, orgId, resourceId, includeDescendants))
    }

    /** 유형·대상(조직·리소스)은 바꾸지 않는다. 다른 대상이면 새 범위를 만든다 */
    fun updateScope(scopeId: Long, scopeName: String, includeDescendants: Boolean): Scope {
        val scope = scope(scopeId)
        if (scopeName.isBlank()) throw BusinessRuleException("범위 이름이 필요합니다")
        val before = scope.snapshot()
        scope.update(scopeName.trim(), includeDescendants)
        changed("SCOPE", scopeId, "UPDATE", before, scope.snapshot())
        return scope
    }

    /** 끈 범위는 판정에서 아무것도 덮지 않는다. 전체(GLOBAL) 범위는 끌 수 없다 */
    fun changeScopeActive(scopeId: Long, active: Boolean): Scope {
        val scope = scope(scopeId)
        if (scope.isActive == active) return scope
        if (scope.scopeType == ScopeType.GLOBAL) throw BusinessRuleException("전체 범위는 끌 수 없습니다")
        val before = scope.snapshot()
        scope.changeActive(active)
        changed("SCOPE", scopeId, if (active) "ACTIVATE" else "DEACTIVATE", before, scope.snapshot())
        return scope
    }

    private fun resource(id: Long) = resourceRepository.findByIdOrNull(id) ?: throw NotFoundException("리소스", id)

    private fun permission(id: Long) = permissionRepository.findByIdOrNull(id) ?: throw NotFoundException("권한", id)

    private fun scope(id: Long) = scopeRepository.findByIdOrNull(id) ?: throw NotFoundException("범위", id)

    private fun changed(target: String, id: Long, action: String, before: Map<String, Any?>?, after: Map<String, Any?>?) =
        eventPublisher.publishEvent(AdminChangeEvent(target, id, action, before, after))

    private fun Role.snapshot() =
        mapOf("roleName" to roleName, "roleType" to roleType.name, "priority" to priority, "isSensitive" to isSensitive, "isPrivileged" to isPrivileged, "isActive" to isActive)

    private fun Resource.snapshot() =
        mapOf("resourceName" to resourceName, "resourceType" to resourceType.name, "resourcePath" to resourcePath, "sensitivity" to sensitivity.name, "isActive" to isActive)

    private fun Permission.snapshot() = mapOf("permissionName" to permissionName, "isActive" to isActive)

    private fun Scope.snapshot() = mapOf("scopeName" to scopeName, "includeDescendants" to includeDescendants, "isActive" to isActive)
}
