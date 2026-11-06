package com.didrakon.iam.authz.role

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant

interface RoleRepository : JpaRepository<Role, Long> {
    fun findByRoleCode(roleCode: String): Role?
}

interface PermissionRepository : JpaRepository<Permission, Long> {
    fun findByResourceIdAndActionAndIsActiveTrue(resourceId: Long, action: PermissionAction): List<Permission>

    fun findByResourceIdInAndIsActiveTrue(resourceIds: Collection<Long>): List<Permission>
}

interface RolePermissionRepository : JpaRepository<RolePermission, Long> {
    fun findByRoleId(roleId: Long): List<RolePermission>

    @Query(
        """
        select rp from RolePermission rp
        where rp.roleId in :roleIds and rp.permissionId in :permissionIds
          and rp.validFrom <= :now and (rp.validUntil is null or rp.validUntil > :now)
        """,
    )
    fun findEffective(
        @Param("roleIds") roleIds: Collection<Long>,
        @Param("permissionIds") permissionIds: Collection<Long>,
        @Param("now") now: Instant,
    ): List<RolePermission>
}
