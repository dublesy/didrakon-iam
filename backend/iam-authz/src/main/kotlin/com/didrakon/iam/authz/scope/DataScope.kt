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

/** scope 에 딸린 데이터 접근 조건 (행 필터, 마스킹). 판정 결과가 아니라 호출 측이 쿼리에 적용할 조건이다 */
@Entity
@Table(name = "data_scope")
class DataScope(
    scopeId: Long,
    dataType: DataType,
    conditionExpression: String? = null,
    maskingPolicy: String? = null,
    rowFilterExpression: String? = null,
) : IdEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "data_scope_id")
    override val id: Long? = null

    @Column(name = "scope_id", nullable = false, updatable = false)
    val scopeId: Long = scopeId

    @Enumerated(EnumType.STRING)
    @Column(name = "data_type", nullable = false, length = 30)
    var dataType: DataType = dataType
        protected set

    @Column(name = "condition_expression", columnDefinition = "json")
    var conditionExpression: String? = conditionExpression
        protected set

    @Column(name = "masking_policy", columnDefinition = "json")
    var maskingPolicy: String? = maskingPolicy
        protected set

    @Column(name = "row_filter_expression", columnDefinition = "json")
    var rowFilterExpression: String? = rowFilterExpression
        protected set

    override fun equals(other: Any?): Boolean = idEquals(other)

    override fun hashCode(): Int = idHashCode()
}

enum class DataType { EMPLOYEE, PAYROLL, CUSTOMER, CONTRACT }
