package com.didrakon.iam.authz.policy

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
 * 정책 버전의 조건 하나. 같은 rule_group 끼리는 AND, 그룹 간은 OR 로 묶는다.
 * 예: (A AND B) OR C → 그룹 1: A, B / 그룹 2: C
 */
@Entity
@Table(name = "policy_rule")
class PolicyRule(
    policyVersionId: Long,
    ruleGroup: Int,
    attributeSource: AttributeSource,
    attributeName: String,
    operator: RuleOperator,
    attributeValue: String?,
    ruleOrder: Int = 0,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "rule_id")
    override val id: Long? = null

    @Column(name = "policy_version_id", nullable = false, updatable = false)
    val policyVersionId: Long = policyVersionId

    @Column(name = "rule_group", nullable = false, updatable = false)
    val ruleGroup: Int = ruleGroup

    @Enumerated(EnumType.STRING)
    @Column(name = "attribute_source", nullable = false, length = 30, updatable = false)
    val attributeSource: AttributeSource = attributeSource

    @Column(name = "attribute_name", nullable = false, length = 200, updatable = false)
    val attributeName: String = attributeName

    @Enumerated(EnumType.STRING)
    @Column(name = "operator", nullable = false, length = 30, updatable = false)
    val operator: RuleOperator = operator

    /** 비교 값 (JSON). EXISTS 는 null */
    @Column(name = "attribute_value", columnDefinition = "json", updatable = false)
    val attributeValue: String? = attributeValue

    @Column(name = "rule_order", nullable = false, updatable = false)
    val ruleOrder: Int = ruleOrder

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class AttributeSource { SUBJECT, RESOURCE, CONTEXT, RELATION, SESSION }

enum class RuleOperator { EQ, NE, IN, NOT_IN, GT, LT, BETWEEN, MATCH, EXISTS }
