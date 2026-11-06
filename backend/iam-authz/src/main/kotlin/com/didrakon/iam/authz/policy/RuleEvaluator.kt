package com.didrakon.iam.authz.policy

import com.didrakon.iam.common.error.BusinessRuleException
import org.springframework.stereotype.Component
import tools.jackson.core.JacksonException
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.math.BigDecimal

/** 판정에 쓰는 속성. 출처(SUBJECT, RESOURCE, …)별로 이름 → 값. RELATION 은 관계 코드 → true */
class Attributes(private val values: Map<AttributeSource, Map<String, Any?>>) {
    fun get(source: AttributeSource, name: String): Any? = values[source]?.get(name)
}

/**
 * [PolicyRule] 을 평가한다. 같은 rule_group 은 AND, 그룹 간은 OR. 규칙이 없으면 항상 참.
 *
 * - 속성이 없으면(null) 규칙은 거짓이다. NE·NOT_IN 도 마찬가지.
 * - 속성이 목록이면 EQ·MATCH 는 "하나라도 맞음", IN 은 "겹침", NOT_IN 은 "겹치지 않음".
 * - GT·LT·BETWEEN 은 숫자끼리 또는 문자열끼리(예: "09:00") 비교한다. BETWEEN 은 양 끝 포함.
 */
@Component
class RuleEvaluator(private val jsonMapper: JsonMapper) {
    fun matches(rules: List<PolicyRule>, attributes: Attributes): Boolean {
        if (rules.isEmpty()) return true
        return rules.groupBy { it.ruleGroup }.values.any { group -> group.all { evaluate(it, attributes) } }
    }

    fun evaluate(rule: PolicyRule, attributes: Attributes): Boolean {
        val actual = normalize(attributes.get(rule.attributeSource, rule.attributeName)) ?: return false
        if (rule.operator == RuleOperator.EXISTS) return actual !is List<*> || actual.isNotEmpty()

        val expected = toValue(parse(rule.attributeValue))
        val candidates = if (actual is List<*>) actual else listOf(actual)
        return when (rule.operator) {
            RuleOperator.EQ -> expected in candidates
            RuleOperator.NE -> expected !in candidates
            RuleOperator.IN -> candidates.any { it in (expected as List<*>) }
            RuleOperator.NOT_IN -> candidates.none { it in (expected as List<*>) }
            RuleOperator.GT -> candidates.any { compare(it, expected)?.let { c -> c > 0 } ?: false }
            RuleOperator.LT -> candidates.any { compare(it, expected)?.let { c -> c < 0 } ?: false }
            RuleOperator.BETWEEN -> {
                val (low, high) = expected as List<*>
                candidates.any { (compare(it, low) ?: -1) >= 0 && (compare(it, high) ?: 1) <= 0 }
            }
            RuleOperator.MATCH -> {
                val regex = Regex(expected as String)
                candidates.any { it is String && regex.matches(it) }
            }
            RuleOperator.EXISTS -> error("위에서 처리")
        }
    }

    /** 규칙 저장 전에 연산자와 값의 모양이 맞는지 확인한다 */
    fun validate(operator: RuleOperator, attributeValue: String?) {
        if (operator == RuleOperator.EXISTS) {
            if (attributeValue != null) throw BusinessRuleException("EXISTS 규칙은 값을 갖지 않습니다")
            return
        }
        val node = try {
            parse(attributeValue)
        } catch (e: JacksonException) {
            throw BusinessRuleException("규칙 값이 올바른 JSON 이 아닙니다: $attributeValue")
        }
        val valid = when (operator) {
            RuleOperator.IN, RuleOperator.NOT_IN -> node.isArray
            RuleOperator.BETWEEN -> node.isArray && node.size() == 2
            RuleOperator.MATCH -> node.isString && runCatching { Regex(node.stringValue()) }.isSuccess
            else -> node.isString || node.isNumber || node.isBoolean
        }
        if (!valid) throw BusinessRuleException("$operator 규칙에 맞지 않는 값입니다: $attributeValue")
    }

    private fun parse(json: String?): JsonNode =
        jsonMapper.readTree(json ?: throw BusinessRuleException("규칙 값이 없습니다"))

    private fun toValue(node: JsonNode): Any? = when {
        node.isArray -> node.values().map(::toValue)
        node.isNumber -> node.decimalValue().stripTrailingZeros()
        node.isBoolean -> node.booleanValue()
        node.isString -> node.stringValue()
        else -> null
    }

    /** 숫자는 BigDecimal, enum 은 이름으로 맞춰 JSON 값과 비교할 수 있게 한다 */
    private fun normalize(value: Any?): Any? = when (value) {
        null -> null
        is Collection<*> -> value.map(::normalize)
        is BigDecimal -> value.stripTrailingZeros()
        is Number -> BigDecimal(value.toString()).stripTrailingZeros()
        is Enum<*> -> value.name
        is Boolean, is String -> value
        else -> value.toString()
    }

    private fun compare(actual: Any?, expected: Any?): Int? = when {
        actual is BigDecimal && expected is BigDecimal -> actual.compareTo(expected)
        actual is String && expected is String -> actual.compareTo(expected)
        else -> null
    }
}
