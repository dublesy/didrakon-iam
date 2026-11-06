package com.didrakon.iam.authz.policy

import jakarta.persistence.LockModeType
import org.springframework.data.jpa.repository.JpaRepository
import org.springframework.data.jpa.repository.Lock
import org.springframework.data.jpa.repository.Query
import org.springframework.data.repository.query.Param

interface PolicyRepository : JpaRepository<Policy, Long> {
    /** 버전 활성화를 직렬화해 ACTIVE 가 2개 생기지 않게 한다 */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select p from Policy p where p.id = :policyId")
    fun findForUpdate(@Param("policyId") policyId: Long): Policy?
}

interface PolicyVersionRepository : JpaRepository<PolicyVersion, Long> {
    fun findByPolicyIdAndStatus(policyId: Long, status: PolicyVersionStatus): List<PolicyVersion>

    fun findByPolicyIdOrderByVersionDesc(policyId: Long): List<PolicyVersion>

    fun findByPolicyIdInAndStatus(policyIds: Collection<Long>, status: PolicyVersionStatus): List<PolicyVersion>

    @Query("select coalesce(max(v.version), 0) from PolicyVersion v where v.policyId = :policyId")
    fun findMaxVersion(@Param("policyId") policyId: Long): Int
}

interface PolicyRuleRepository : JpaRepository<PolicyRule, Long> {
    fun findByPolicyVersionIdIn(policyVersionIds: Collection<Long>): List<PolicyRule>
}

interface PolicyTargetRepository : JpaRepository<PolicyTarget, Long> {
    fun findByPolicyId(policyId: Long): List<PolicyTarget>

    @Query(
        """
        select t from PolicyTarget t
        where t.permissionId in :permissionIds or t.resourceId in :resourceIds or t.roleId in :roleIds
        """,
    )
    fun findMatching(
        @Param("permissionIds") permissionIds: Collection<Long>,
        @Param("resourceIds") resourceIds: Collection<Long>,
        @Param("roleIds") roleIds: Collection<Long>,
    ): List<PolicyTarget>
}

interface PolicyExceptionRepository : JpaRepository<PolicyException, Long> {
    fun findByPolicyIdIn(policyIds: Collection<Long>): List<PolicyException>
}
