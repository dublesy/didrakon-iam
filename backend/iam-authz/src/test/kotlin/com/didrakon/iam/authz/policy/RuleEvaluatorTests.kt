package com.didrakon.iam.authz.policy

import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.common.error.BusinessRuleException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import tools.jackson.databind.json.JsonMapper
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RuleEvaluatorTests {
    private val evaluator = RuleEvaluator(JsonMapper.builder().build())

    private val attributes = Attributes(
        mapOf(
            AttributeSource.SUBJECT to mapOf("companyOrgIds" to listOf(10L, 20L), "isManager" to true, "nothing" to null),
            AttributeSource.RESOURCE to mapOf("sensitivity" to Sensitivity.SECRET, "resourceKey" to "payroll.export"),
            AttributeSource.CONTEXT to mapOf("country" to "KR", "riskScore" to 70, "time" to "09:30"),
            AttributeSource.RELATION to mapOf("OWNS" to true),
        ),
    )

    @Test
    fun `EQ·NE 는 스칼라를 비교하고 enum 은 이름으로 비교한다`() {
        assertTrue(eval(AttributeSource.CONTEXT, "country", RuleOperator.EQ, "\"KR\""))
        assertFalse(eval(AttributeSource.CONTEXT, "country", RuleOperator.NE, "\"KR\""))
        assertTrue(eval(AttributeSource.RESOURCE, "sensitivity", RuleOperator.EQ, "\"SECRET\""))
        assertTrue(eval(AttributeSource.SUBJECT, "isManager", RuleOperator.EQ, "true"))
    }

    @Test
    fun `목록 속성은 EQ 면 포함, IN 이면 겹침, NOT_IN 이면 겹치지 않음`() {
        assertTrue(eval(AttributeSource.SUBJECT, "companyOrgIds", RuleOperator.EQ, "20"))
        assertTrue(eval(AttributeSource.SUBJECT, "companyOrgIds", RuleOperator.IN, "[5, 10]"))
        assertFalse(eval(AttributeSource.SUBJECT, "companyOrgIds", RuleOperator.NOT_IN, "[5, 10]"))
        assertTrue(eval(AttributeSource.SUBJECT, "companyOrgIds", RuleOperator.NOT_IN, "[5, 6]"))
    }

    @Test
    fun `GT·LT·BETWEEN 은 숫자끼리, 문자열끼리 비교한다`() {
        assertTrue(eval(AttributeSource.CONTEXT, "riskScore", RuleOperator.GT, "50"))
        assertFalse(eval(AttributeSource.CONTEXT, "riskScore", RuleOperator.LT, "70"))
        assertTrue(eval(AttributeSource.CONTEXT, "riskScore", RuleOperator.BETWEEN, "[70, 80]"))
        assertTrue(eval(AttributeSource.CONTEXT, "time", RuleOperator.BETWEEN, "[\"09:00\", \"18:00\"]"))
        assertFalse(eval(AttributeSource.CONTEXT, "time", RuleOperator.GT, "10"))
    }

    @Test
    fun `MATCH 는 정규식 전체 일치, EXISTS 는 값이 있는지 본다`() {
        assertTrue(eval(AttributeSource.RESOURCE, "resourceKey", RuleOperator.MATCH, "\"payroll\\\\..*\""))
        assertTrue(eval(AttributeSource.RELATION, "OWNS", RuleOperator.EXISTS, null))
        assertFalse(eval(AttributeSource.RELATION, "MANAGES", RuleOperator.EXISTS, null))
    }

    @Test
    fun `속성이 없으면 NE·NOT_IN 을 포함해 모두 거짓이다`() {
        assertFalse(eval(AttributeSource.SUBJECT, "nothing", RuleOperator.NE, "\"x\""))
        assertFalse(eval(AttributeSource.SESSION, "authLevel", RuleOperator.NOT_IN, "[\"MFA\"]"))
    }

    @Test
    fun `같은 그룹은 AND, 그룹 간은 OR 이고 규칙이 없으면 참이다`() {
        val korea = rule(1, AttributeSource.CONTEXT, "country", RuleOperator.EQ, "\"KR\"")
        val highRisk = rule(1, AttributeSource.CONTEXT, "riskScore", RuleOperator.GT, "90")
        val owner = rule(2, AttributeSource.RELATION, "OWNS", RuleOperator.EXISTS, null)

        assertFalse(evaluator.matches(listOf(korea, highRisk), attributes))
        assertTrue(evaluator.matches(listOf(korea, highRisk, owner), attributes))
        assertTrue(evaluator.matches(emptyList(), attributes))
    }

    @Test
    fun `연산자에 맞지 않는 값은 저장 전에 거부한다`() {
        assertThrows<BusinessRuleException> { evaluator.validate(RuleOperator.IN, "\"KR\"") }
        assertThrows<BusinessRuleException> { evaluator.validate(RuleOperator.BETWEEN, "[1]") }
        assertThrows<BusinessRuleException> { evaluator.validate(RuleOperator.EXISTS, "true") }
        assertThrows<BusinessRuleException> { evaluator.validate(RuleOperator.MATCH, "\"[\"") }
        assertThrows<BusinessRuleException> { evaluator.validate(RuleOperator.EQ, "{not json") }
        evaluator.validate(RuleOperator.EQ, "\"KR\"")
    }

    private fun eval(source: AttributeSource, name: String, operator: RuleOperator, value: String?): Boolean =
        evaluator.evaluate(rule(1, source, name, operator, value), attributes)

    private fun rule(group: Int, source: AttributeSource, name: String, operator: RuleOperator, value: String?) =
        PolicyRule(1, group, source, name, operator, value)
}
