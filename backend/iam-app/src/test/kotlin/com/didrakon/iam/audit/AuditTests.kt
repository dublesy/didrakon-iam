package com.didrakon.iam.audit

import com.didrakon.iam.audit.query.AuditQueryService
import com.didrakon.iam.audit.query.AuditSearch
import com.didrakon.iam.audit.record.AuditEventType
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.assignment.RoleChangeType
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.Policy
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.common.context.RequestContext
import com.didrakon.iam.common.context.RequestContextHolder
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import jakarta.persistence.EntityManager
import org.springframework.beans.factory.annotation.Autowired
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertNull

/** 업무 변경이 같은 트랜잭션 안에서 감사 기록으로 남는지 확인한다 (테스트 트랜잭션은 커밋 전에 검증하고 롤백한다) */
@AuthzTest
class AuditTests @Autowired constructor(
    private val auditQueryService: AuditQueryService,
    private val assignmentService: RoleAssignmentService,
    private val organizationRoleService: OrganizationRoleService,
    private val membershipService: MembershipService,
    private val groupMemberService: GroupMemberService,
    private val groupRepository: UserGroupRepository,
    private val policyRepository: PolicyRepository,
    private val policyVersionService: PolicyVersionService,
    private val fixture: AuthzFixture,
    private val jsonMapper: JsonMapper,
    private val entityManager: EntityManager,
) {
    @Test
    fun `역할 부여·회수는 변경 이력과 감사 이벤트로 남고 요청 컨텍스트가 함께 기록된다`() {
        val admin = fixture.user("관리자")
        val userId = fixture.user()
        val roleId = fixture.role().requireId()

        asAdmin(admin) {
            val assignment = assignmentService.assignDirect(userId, roleId, reason = "업무 필요")
            assignmentService.revoke(assignment.requireId(), reason = "업무 종료")
        }

        val history = auditQueryService.roleHistory(userId)
        assertEquals(listOf(RoleChangeType.REVOKE, RoleChangeType.ASSIGN), history.map { it.changeType })
        assertEquals(listOf(admin, admin), history.map { it.changedBy })

        val events = search(userId, AuditEventType.ROLE_CHANGE)
        assertEquals(listOf("REVOKE", "ASSIGN"), events.map { it.action })
        assertEquals(admin, events.first().actorSubjectId)
        assertEquals("trace-admin", events.first().traceId)
        assertEquals("10.0.0.1", events.first().ipAddress)
        assertEquals("DIRECT", json(events.last().afterValue)["sourceType"].stringValue())
    }

    @Test
    fun `소속 변경으로 생긴 조직 역할 할당은 그 변경을 일으킨 행위자로 남는다`() {
        val admin = fixture.user("관리자")
        val company = fixture.org(OrgType.COMPANY)
        organizationRoleService.create(company, fixture.role().requireId())
        val userId = fixture.user()

        asAdmin(admin) { fixture.join(userId, company) }

        val roleChange = search(userId, AuditEventType.ROLE_CHANGE).single()
        assertEquals(admin, roleChange.actorSubjectId)
        assertEquals("ORGANIZATION", json(roleChange.afterValue)["sourceType"].stringValue())
        val join = search(userId, AuditEventType.MEMBERSHIP_CHANGE).single()
        assertEquals("JOIN", join.action)
        assertEquals(company, json(join.afterValue)["orgId"].longValue())
    }

    @Test
    fun `전적은 이전 조직과 새 조직을 담은 TRANSFER 이벤트로 남는다`() {
        val companyA = fixture.org(OrgType.COMPANY)
        val companyB = fixture.org(OrgType.COMPANY)
        val userId = fixture.user().also { fixture.join(it, companyA) }

        membershipService.transferPrimary(userId, companyB)

        val transfer = search(userId, AuditEventType.MEMBERSHIP_CHANGE).first { it.action == "TRANSFER" }
        assertEquals(companyA, json(transfer.beforeValue)["orgId"].longValue())
        assertEquals(companyB, json(transfer.afterValue)["orgId"].longValue())
        assertNull(transfer.actorSubjectId)
    }

    @Test
    fun `그룹 구성원 추가와 제거가 남는다`() {
        val group = groupRepository.save(UserGroup("G-${System.nanoTime()}", "그룹", GroupType.STATIC))
        val userId = fixture.user()

        groupMemberService.addMember(group.requireId(), userId)
        groupMemberService.removeMember(group.requireId(), userId)

        assertEquals(listOf("REMOVE", "ADD"), search(userId, AuditEventType.MEMBERSHIP_CHANGE).map { it.action })
    }

    @Test
    fun `정책 활성화는 이전·새 버전의 규칙 스냅샷과 함께 이력으로 남는다`() {
        val admin = fixture.user("관리자")
        val policyId = policyRepository.save(Policy("P-${System.nanoTime()}", "해외 차단", PolicyType.SECURITY, PolicyEffect.DENY)).requireId()
        val korea = RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.NE, "\"KR\"")
        val koreaOrJapan = RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.NOT_IN, "[\"KR\", \"JP\"]")

        asAdmin(admin) {
            policyVersionService.activate(policyVersionService.createVersion(policyId, listOf(korea)).requireId())
            policyVersionService.activate(policyVersionService.createVersion(policyId, listOf(koreaOrJapan), "일본 허용").requireId())
        }

        entityManager.flush()
        entityManager.clear()
        val history = auditQueryService.policyHistory(policyId)
        assertEquals(listOf(1 to 2, null to 1), history.map { it.oldVersion to it.newVersion })
        val latest = history.first()
        assertEquals(admin, latest.changedBy)
        assertEquals("일본 허용", latest.changeReason)
        assertEquals("NE", json(latest.oldValue)["rules"][0]["operator"].stringValue())
        val newValue = json(latest.newValue)
        assertEquals(listOf("KR", "JP"), newValue["rules"][0]["attributeValue"].values().map { it.stringValue() })
        assertEquals("DENY", newValue["effect"].stringValue())
        assertEquals(2, newValue["version"].intValue())
    }

    @Test
    fun `감사 검색은 기간·유형·건수로 거르고 잘못된 조건은 거부한다`() {
        val userId = fixture.user()
        val roleId = fixture.role().requireId()
        assignmentService.assignDirect(userId, roleId)
        fixture.join(userId, fixture.org(OrgType.COMPANY))

        assertEquals(2, search(userId).size)
        assertEquals(1, search(userId, AuditEventType.MEMBERSHIP_CHANGE).size)
        assertEquals(1, auditQueryService.search(AuditSearch(past(), future(), subjectId = userId, limit = 1)).size)
        assertEquals(0, auditQueryService.search(AuditSearch(future(), future().plusSeconds(60), subjectId = userId)).size)

        assertThrows<BusinessRuleException> { auditQueryService.search(AuditSearch(future(), past())) }
        assertThrows<BusinessRuleException> { auditQueryService.search(AuditSearch(past(), future(), limit = 0)) }
    }

    private fun json(value: String?): JsonNode = jsonMapper.readTree(value ?: throw AssertionError("JSON 값이 없습니다"))

    private fun asAdmin(admin: Long, block: () -> Unit) =
        RequestContextHolder.runWith(RequestContext(actorSubjectId = admin, traceId = "trace-admin", ipAddress = "10.0.0.1"), block)

    private fun search(subjectId: Long, vararg types: AuditEventType) =
        auditQueryService.search(AuditSearch(past(), future(), subjectId = subjectId, eventTypes = types.toSet()))

    private fun past(): Instant = Instant.now().minus(1, ChronoUnit.HOURS)

    private fun future(): Instant = Instant.now().plus(1, ChronoUnit.HOURS)
}
