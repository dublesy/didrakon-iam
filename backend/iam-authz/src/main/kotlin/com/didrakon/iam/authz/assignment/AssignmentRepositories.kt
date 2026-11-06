package com.didrakon.iam.authz.assignment

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant

interface RoleAssignmentRepository : JpaRepository<RoleAssignment, Long> {
    @Query(
        """
        select a from RoleAssignment a
        where a.subjectId = :subjectId
          and a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE
          and a.validFrom <= :now and (a.validUntil is null or a.validUntil > :now)
        """,
    )
    fun findEffective(@Param("subjectId") subjectId: Long, @Param("now") now: Instant): List<RoleAssignment>

    /** 지금 유효하거나 앞으로 시작할 할당 (승인된 JIT·시작 전 위임 포함) */
    @Query(
        """
        select a from RoleAssignment a
        where a.subjectId = :subjectId
          and a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE
          and (a.validUntil is null or a.validUntil > :now)
        """,
    )
    fun findCurrentOrUpcoming(@Param("subjectId") subjectId: Long, @Param("now") now: Instant): List<RoleAssignment>

    @Query(
        """
        select a from RoleAssignment a
        where a.subjectId = :subjectId and a.sourceType = :sourceType
          and a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE
        """,
    )
    fun findActiveBySource(
        @Param("subjectId") subjectId: Long,
        @Param("sourceType") sourceType: AssignmentSourceType,
    ): List<RoleAssignment>

    @Query(
        """
        select a from RoleAssignment a
        where a.sourceType = :sourceType and a.sourceId = :sourceId
          and a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE
        """,
    )
    fun findActiveBySourceId(
        @Param("sourceType") sourceType: AssignmentSourceType,
        @Param("sourceId") sourceId: Long,
    ): List<RoleAssignment>

    @Query(
        """
        select a from RoleAssignment a
        where a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE and a.validUntil <= :now
        """,
    )
    fun findExpiredButActive(@Param("now") now: Instant): List<RoleAssignment>

    /** 지금 효력이 있는 모든 할당. [roleId] 를 주면 그 역할만 (접근 재검토 대상 수집용) */
    @Query(
        """
        select a from RoleAssignment a
        where a.status = com.didrakon.iam.authz.assignment.AssignmentStatus.ACTIVE
          and a.validFrom <= :now and (a.validUntil is null or a.validUntil > :now)
          and (:roleId is null or a.roleId = :roleId)
        order by a.id
        """,
    )
    fun findAllEffective(@Param("now") now: Instant, @Param("roleId") roleId: Long?): List<RoleAssignment>
}

interface OrganizationRoleRepository : JpaRepository<OrganizationRole, Long> {
    fun findByOrgIdInAndIsActiveTrue(orgIds: Collection<Long>): List<OrganizationRole>

    fun findByOrgId(orgId: Long): List<OrganizationRole>

    fun existsByRoleIdAndIsActiveTrue(roleId: Long): Boolean
}

interface GroupRoleRepository : JpaRepository<GroupRole, Long> {
    fun findByGroupIdIn(groupIds: Collection<Long>): List<GroupRole>

    fun existsByRoleId(roleId: Long): Boolean
}
