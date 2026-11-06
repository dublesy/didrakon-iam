package com.didrakon.iam.authz.policy

import com.didrakon.iam.common.jpa.BaseCreatedEntity
import com.didrakon.iam.common.jpa.BaseTimeEntity
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
 * ABAC 정책. 권한을 새로 주지 않고 RBAC 이 허용한 요청을 제한한다.
 * 규칙은 버전([PolicyVersion])마다 있고, ACTIVE 버전만 판정에 쓴다.
 */
@Entity
@Table(name = "policy")
class Policy(
    policyCode: String,
    policyName: String,
    policyType: PolicyType,
    effect: PolicyEffect,
    priority: Int = 0,
) : BaseTimeEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "policy_id")
    override val id: Long? = null

    @Column(name = "policy_code", nullable = false, length = 100, updatable = false)
    val policyCode: String = policyCode

    @Column(name = "policy_name", nullable = false, length = 200)
    var policyName: String = policyName
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "policy_type", nullable = false, length = 30)
    var policyType: PolicyType = policyType
        protected set

    @Enumerated(EnumType.STRING)
    @Column(name = "effect", nullable = false, length = 30)
    var effect: PolicyEffect = effect
        protected set

    /** 표시 순서·설명용. 판정 로직은 이 값을 읽지 않는다 (ERD 결정 사항 4) */
    @Column(name = "priority", nullable = false)
    var priority: Int = priority
        protected set

    @Column(name = "is_active", nullable = false)
    var isActive: Boolean = true
        protected set

    internal fun update(policyName: String, priority: Int) {
        this.policyName = policyName
        this.priority = priority
    }

    internal fun changeActive(active: Boolean) {
        isActive = active
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class PolicyType { AUTHORIZATION, SECURITY, DATA, RISK }

/**
 * 조건이 맞을 때의 효과. ALLOW 는 "조건을 만족할 때만 허용"하는 조건부 허용이라
 * 조건이 맞지 않으면 DENY 가 된다 (정책으로 권한이 새로 생기지는 않는다).
 */
enum class PolicyEffect { ALLOW, DENY, CHALLENGE, REQUIRE_APPROVAL }

@Entity
@Table(name = "policy_version")
class PolicyVersion(
    policyId: Long,
    version: Int,
    changeReason: String? = null,
    createdBy: Long? = null,
) : BaseCreatedEntity(), IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "policy_version_id")
    override val id: Long? = null

    @Column(name = "policy_id", nullable = false, updatable = false)
    val policyId: Long = policyId

    @Column(name = "version", nullable = false, updatable = false)
    val version: Int = version

    /** 정책당 ACTIVE 는 1개 ([PolicyVersionService] 가 보장) */
    @Enumerated(EnumType.STRING)
    @Column(name = "status", nullable = false, length = 30)
    var status: PolicyVersionStatus = PolicyVersionStatus.DRAFT
        protected set

    @Column(name = "change_reason", length = 1000, updatable = false)
    val changeReason: String? = changeReason

    @Column(name = "created_by", updatable = false)
    val createdBy: Long? = createdBy

    internal fun activate() {
        status = PolicyVersionStatus.ACTIVE
    }

    internal fun retire() {
        status = PolicyVersionStatus.RETIRED
    }

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class PolicyVersionStatus { DRAFT, ACTIVE, RETIRED }
