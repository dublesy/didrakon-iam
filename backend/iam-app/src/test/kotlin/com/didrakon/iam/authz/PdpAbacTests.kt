package com.didrakon.iam.authz

import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.Policy
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyException
import com.didrakon.iam.authz.policy.PolicyExceptionRepository
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyTarget
import com.didrakon.iam.authz.policy.PolicyTargetRepository
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.resource.RelationType
import com.didrakon.iam.authz.resource.RelationTypeRepository
import com.didrakon.iam.authz.resource.Resource
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.resource.SubjectRelation
import com.didrakon.iam.authz.resource.SubjectRelationRepository
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import java.time.Instant
import kotlin.test.assertEquals

/** RBAC 으로 허용된 요청에 ABAC 정책이 제한을 거는지 확인한다 */
@AuthzTest
class PdpAbacTests @Autowired constructor(
    private val pdp: PolicyDecisionPoint,
    private val assignmentService: RoleAssignmentService,
    private val policyRepository: PolicyRepository,
    private val targetRepository: PolicyTargetRepository,
    private val exceptionRepository: PolicyExceptionRepository,
    private val versionService: PolicyVersionService,
    private val relationTypeRepository: RelationTypeRepository,
    private val subjectRelationRepository: SubjectRelationRepository,
    private val fixture: AuthzFixture,
    private val userService: UserService,
) {
    @Test
    fun `정책은 사용자 구분(userKind)으로 외부 사용자만 막을 수 있다`() {
        val resource = fixture.resource()
        val role = fixture.roleAllowing(resource.requireId())
        val employee = fixture.user()
        val external = userService.create(
            null, "외부 사용자", "ext-${System.nanoTime()}@customer.example.com", null, null, UserKind.EXTERNAL, fixture.org(OrgType.COMPANY),
        ).requireId()
        listOf(employee, external).forEach { assignmentService.assignDirect(it, role.requireId()) }
        policy(PolicyEffect.DENY, resource, RuleSpec(1, AttributeSource.SUBJECT, "userKind", RuleOperator.EQ, "\"EXTERNAL\""))

        assertEquals(Decision.ALLOW, decide(employee, resource).decision)
        assertEquals(Decision.DENY, decide(external, resource).decision)
    }

    @Test
    fun `DENY 정책은 조건이 맞을 때만 거부한다`() {
        val (userId, resource) = allowedUserAndResource()
        policy(PolicyEffect.DENY, resource, RuleSpec(1, AttributeSource.CONTEXT, "country", RuleOperator.NE, "\"KR\""))

        assertEquals(Decision.ALLOW, decide(userId, resource, context = mapOf("country" to "KR")).decision)
        val denied = decide(userId, resource, context = mapOf("country" to "US"))
        assertEquals(Decision.DENY, denied.decision)
    }

    @Test
    fun `조건부 허용(ALLOW) 정책은 조건을 만족하지 못하면 거부한다`() {
        val company = fixture.org(OrgType.COMPANY)
        val otherCompany = fixture.org(OrgType.COMPANY)
        val resource = fixture.resource()
        val role = fixture.roleAllowing(resource.requireId())
        val insider = fixture.user().also { fixture.join(it, company) }
        val outsider = fixture.user().also { fixture.join(it, otherCompany) }
        listOf(insider, outsider).forEach { assignmentService.assignDirect(it, role.requireId()) }
        val policyId = policy(PolicyEffect.ALLOW, resource, RuleSpec(1, AttributeSource.SUBJECT, "companyOrgIds", RuleOperator.EQ, "$company"))

        assertEquals(Decision.ALLOW, decide(insider, resource).decision)
        val denied = decide(outsider, resource)
        assertEquals(Decision.DENY, denied.decision)
        assertEquals(policyId, denied.matchedPolicyId)
    }

    @Test
    fun `여러 정책이 걸리면 가장 강한 효과를 택한다`() {
        val (userId, resource) = allowedUserAndResource(Sensitivity.SECRET)
        policy(PolicyEffect.CHALLENGE, resource, RuleSpec(1, AttributeSource.SESSION, "authLevel", RuleOperator.NE, "\"MFA\""))
        val secretDeny = policy(
            PolicyEffect.DENY, resource,
            RuleSpec(1, AttributeSource.RESOURCE, "sensitivity", RuleOperator.EQ, "\"SECRET\""),
            RuleSpec(1, AttributeSource.CONTEXT, "network", RuleOperator.EQ, "\"EXTERNAL\""),
        )

        assertEquals(Decision.CHALLENGE, decide(userId, resource, session = mapOf("authLevel" to "PASSWORD")).decision)
        assertEquals(Decision.ALLOW, decide(userId, resource, session = mapOf("authLevel" to "MFA")).decision)
        val both = decide(userId, resource, context = mapOf("network" to "EXTERNAL"), session = mapOf("authLevel" to "PASSWORD"))
        assertEquals(Decision.DENY, both.decision)
        assertEquals(secretDeny, both.matchedPolicyId)
    }

    @Test
    fun `정책 예외에 해당하는 subject 에게는 그 정책을 적용하지 않는다`() {
        val (userId, resource) = allowedUserAndResource()
        val policyId = policy(PolicyEffect.DENY, resource)
        assertEquals(Decision.DENY, decide(userId, resource).decision)

        exceptionRepository.save(PolicyException(policyId, userId, null, "감사 대응", Instant.now().minusSeconds(60)))

        assertEquals(Decision.ALLOW, decide(userId, resource).decision)
    }

    @Test
    fun `ACTIVE 버전이 없는 정책은 적용하지 않는다`() {
        val (userId, resource) = allowedUserAndResource()
        policy(PolicyEffect.DENY, resource, activate = false)

        assertEquals(Decision.ALLOW, decide(userId, resource).decision)
    }

    @Test
    fun `상위 리소스를 대상으로 한 정책은 하위 리소스 요청에도 적용된다`() {
        val clientId = fixture.client()
        val system = fixture.resource(clientId)
        val menu = fixture.resource(clientId, parentId = system.requireId())
        val userId = fixture.user()
        assignmentService.assignDirect(userId, fixture.roleAllowing(menu.requireId()).requireId())
        policy(PolicyEffect.REQUIRE_APPROVAL, system)

        assertEquals(Decision.REQUIRE_APPROVAL, decide(userId, menu).decision)
    }

    @Test
    fun `관계(ReBAC) 조건을 쓰고 판정 로그에 매칭된 관계를 남긴다`() {
        val (owner, resource) = allowedUserAndResource()
        val relationType = relationTypeRepository.save(RelationType("OWNS-${System.nanoTime()}", "소유"))
        val relation = subjectRelationRepository.save(
            SubjectRelation.toResource(owner, relationType.requireId(), resource.requireId(), Instant.now().minusSeconds(60)),
        )
        policy(PolicyEffect.CHALLENGE, resource, RuleSpec(1, AttributeSource.RELATION, relationType.relationCode, RuleOperator.EXISTS, null))

        val result = decide(owner, resource)

        assertEquals(Decision.CHALLENGE, result.decision)
        assertEquals(relation.requireId(), result.matchedRelationId)
    }

    @Test
    fun `역할을 대상으로 한 정책은 그 역할로 허용된 요청에만 적용된다`() {
        val resource = fixture.resource()
        val privileged = fixture.roleAllowing(resource.requireId())
        val normal = fixture.roleAllowing(resource.requireId())
        val privilegedUser = fixture.user().also { assignmentService.assignDirect(it, privileged.requireId()) }
        val normalUser = fixture.user().also { assignmentService.assignDirect(it, normal.requireId()) }
        val policyId = policyRepository.save(Policy("P-${System.nanoTime()}", "특권 역할 승인", PolicyType.SECURITY, PolicyEffect.REQUIRE_APPROVAL)).requireId()
        targetRepository.save(PolicyTarget.role(policyId, privileged.requireId()))
        versionService.activate(versionService.createVersion(policyId, emptyList()).requireId())

        assertEquals(Decision.REQUIRE_APPROVAL, decide(privilegedUser, resource).decision)
        assertEquals(Decision.ALLOW, decide(normalUser, resource).decision)
    }

    private fun allowedUserAndResource(sensitivity: Sensitivity = Sensitivity.INTERNAL): Pair<Long, Resource> {
        val resource = fixture.resource(sensitivity = sensitivity)
        val userId = fixture.user()
        assignmentService.assignDirect(userId, fixture.roleAllowing(resource.requireId()).requireId())
        return userId to resource
    }

    /** 리소스를 대상으로 하는 정책을 만들고 규칙 버전을 활성화한다 */
    private fun policy(effect: PolicyEffect, target: Resource, vararg rules: RuleSpec, activate: Boolean = true): Long {
        val policyId = policyRepository.save(Policy("P-${System.nanoTime()}", "정책", PolicyType.AUTHORIZATION, effect)).requireId()
        targetRepository.save(PolicyTarget.resource(policyId, target.requireId()))
        val version = versionService.createVersion(policyId, rules.toList())
        if (activate) versionService.activate(version.requireId())
        return policyId
    }

    private fun decide(
        subjectId: Long,
        resource: Resource,
        context: Map<String, Any?> = emptyMap(),
        session: Map<String, Any?> = emptyMap(),
    ) = pdp.decide(AuthorizationRequest(subjectId, resource.requireId(), PermissionAction.READ, context = context, session = session))
}
