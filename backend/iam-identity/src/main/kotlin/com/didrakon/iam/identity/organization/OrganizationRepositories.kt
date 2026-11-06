package com.didrakon.iam.identity.organization

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface OrganizationRepository : JpaRepository<Organization, Long> {
    fun findByOrgCode(orgCode: String): Organization?

    /** 자기 자신을 포함한 하위 조직 전체의 ID */
    @Query(
        nativeQuery = true,
        value = """
            WITH RECURSIVE subtree (org_id) AS (
                SELECT org_id FROM organization WHERE org_id = :orgId
                UNION ALL
                SELECT o.org_id FROM organization o JOIN subtree s ON o.parent_org_id = s.org_id
            )
            SELECT org_id FROM subtree
        """,
    )
    fun findSubtreeIds(@Param("orgId") orgId: Long): List<Long>

    /** 자기 자신을 포함한 상위 조직 전체의 ID */
    @Query(
        nativeQuery = true,
        value = """
            WITH RECURSIVE ancestors (org_id, parent_org_id) AS (
                SELECT org_id, parent_org_id FROM organization WHERE org_id = :orgId
                UNION ALL
                SELECT o.org_id, o.parent_org_id FROM organization o JOIN ancestors a ON o.org_id = a.parent_org_id
            )
            SELECT org_id FROM ancestors
        """,
    )
    fun findAncestorIds(@Param("orgId") orgId: Long): List<Long>
}

interface SubjectOrganizationRepository : JpaRepository<SubjectOrganization, Long> {
    @Query(
        """
        select m from SubjectOrganization m
        where m.subjectId = :subjectId
          and m.membershipType = com.didrakon.iam.identity.organization.MembershipType.PRIMARY
          and m.validUntil is null
        """,
    )
    fun findActivePrimary(@Param("subjectId") subjectId: Long): SubjectOrganization?

    @Query("select m from SubjectOrganization m where m.subjectId = :subjectId and m.validUntil is null")
    fun findActiveBySubjectId(@Param("subjectId") subjectId: Long): List<SubjectOrganization>

    @Query("select m from SubjectOrganization m where m.subjectId in :subjectIds and m.validUntil is null")
    fun findActiveBySubjectIdIn(@Param("subjectIds") subjectIds: Collection<Long>): List<SubjectOrganization>

    @Query("select m from SubjectOrganization m where m.orgId in :orgIds and m.validUntil is null")
    fun findActiveByOrgIdIn(@Param("orgIds") orgIds: Collection<Long>): List<SubjectOrganization>
}
