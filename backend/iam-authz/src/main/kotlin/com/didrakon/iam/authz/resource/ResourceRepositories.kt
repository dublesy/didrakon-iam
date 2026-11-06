package com.didrakon.iam.authz.resource

import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param
import java.time.Instant

interface ResourceRepository : JpaRepository<Resource, Long> {
    fun findByClientIdAndResourceKey(clientId: Long, resourceKey: String): Resource?

    fun findByClientId(clientId: Long): List<Resource>

    /** 자기 자신을 포함한 상위 리소스 전체의 ID */
    @Query(
        nativeQuery = true,
        value = """
            WITH RECURSIVE ancestors (resource_id, parent_resource_id) AS (
                SELECT resource_id, parent_resource_id FROM resource WHERE resource_id = :resourceId
                UNION ALL
                SELECT r.resource_id, r.parent_resource_id FROM resource r JOIN ancestors a ON r.resource_id = a.parent_resource_id
            )
            SELECT resource_id FROM ancestors
        """,
    )
    fun findAncestorIds(@Param("resourceId") resourceId: Long): List<Long>
}

interface RelationTypeRepository : JpaRepository<RelationType, Long> {
    fun findByRelationCode(relationCode: String): RelationType?
}

interface ResourceRelationRepository : JpaRepository<ResourceRelation, Long>

interface SubjectRelationRepository : JpaRepository<SubjectRelation, Long> {
    @Query(
        """
        select r from SubjectRelation r
        where r.subjectId = :subjectId and r.targetResourceId = :resourceId
          and r.validFrom <= :now and (r.validUntil is null or r.validUntil > :now)
        """,
    )
    fun findEffectiveToResource(
        @Param("subjectId") subjectId: Long,
        @Param("resourceId") resourceId: Long,
        @Param("now") now: Instant,
    ): List<SubjectRelation>
}
