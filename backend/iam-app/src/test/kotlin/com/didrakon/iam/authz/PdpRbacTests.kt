package com.didrakon.iam.authz

import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Instant
import kotlin.test.assertEquals

@AuthzTest
class PdpRbacTests @Autowired constructor(
    private val pdp: PolicyDecisionPoint,
    private val assignmentService: RoleAssignmentService,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
    private val userService: UserService,
) {
    @Test
    fun `사용 중이 아닌 사용자는 역할이 있어도 거부한다`() {
        val userId = fixture.user()
        val resource = fixture.resource()
        assignmentService.assignDirect(userId, fixture.roleAllowing(resource.requireId()).requireId())
        assertEquals(Decision.ALLOW, decide(userId, resource.requireId()).decision)

        userService.changeStatus(userId, SubjectStatus.DISABLED)

        val result = decide(userId, resource.requireId())
        assertEquals(Decision.DENY, result.decision)
        assertEquals("사용 중이 아닌 사용자입니다: DISABLED", result.reason)
    }

    @Test
    fun `역할의 권한으로 허용하고 근거와 함께 판정 로그를 남긴다`() {
        val userId = fixture.user()
        val resource = fixture.resource()
        val role = fixture.roleAllowing(resource.requireId())
        val assignment = assignmentService.assignDirect(userId, role.requireId())

        val result = pdp.decide(AuthorizationRequest(userId, resource.requireId(), PermissionAction.READ, traceId = "trace-1"))

        assertEquals(Decision.ALLOW, result.decision)
        assertEquals(assignment.requireId(), result.matchedAssignmentId)
        assertEquals(role.requireId(), result.matchedRoleId)
        val logged = jdbc.queryForMap("SELECT decision, matched_assignment_id, explanation FROM authorization_log WHERE trace_id = 'trace-1'")
        assertEquals("ALLOW", logged["decision"])
        assertEquals(assignment.requireId(), (logged["matched_assignment_id"] as Number).toLong())
    }

    @Test
    fun `할당이 없거나 행위에 맞는 권한이 없으면 거부한다`() {
        val userId = fixture.user()
        val resource = fixture.resource()
        val role = fixture.roleAllowing(resource.requireId(), PermissionAction.READ)

        assertEquals(Decision.DENY, decide(userId, resource.requireId()).decision)

        assignmentService.assignDirect(userId, role.requireId())
        assertEquals(Decision.DENY, decide(userId, resource.requireId(), PermissionAction.DELETE).decision)
    }

    @Test
    fun `DENY 권한이 매칭되면 다른 역할의 허용보다 우선한다`() {
        val userId = fixture.user()
        val resource = fixture.resource()
        assignmentService.assignDirect(userId, fixture.roleAllowing(resource.requireId()).requireId())
        val denyRole = fixture.roleAllowing(resource.requireId(), effect = PermissionEffect.DENY)
        assignmentService.assignDirect(userId, denyRole.requireId())

        val result = decide(userId, resource.requireId())

        assertEquals(Decision.DENY, result.decision)
        assertEquals(denyRole.requireId(), result.matchedRoleId)
    }

    @Test
    fun `조직 scope 는 대상 조직이 그 조직이나 하위 조직일 때만 허용한다`() {
        val companyA = fixture.org(OrgType.COMPANY)
        val teamA = fixture.org(OrgType.TEAM, companyA)
        val companyB = fixture.org(OrgType.COMPANY)
        val userId = fixture.user()
        val resource = fixture.resource()
        val role = fixture.roleAllowing(resource.requireId())
        assignmentService.assignDirect(userId, role.requireId(), fixture.orgScope(companyA, includeDescendants = true).requireId())

        assertEquals(Decision.ALLOW, decide(userId, resource.requireId(), orgId = teamA).decision)
        assertEquals(Decision.DENY, decide(userId, resource.requireId(), orgId = companyB).decision)
        assertEquals(Decision.DENY, decide(userId, resource.requireId(), orgId = null).decision)
    }

    @Test
    fun `하위 미포함 조직 scope 는 그 조직만 덮는다`() {
        val company = fixture.org(OrgType.COMPANY)
        val team = fixture.org(OrgType.TEAM, company)
        val userId = fixture.user()
        val resource = fixture.resource()
        assignmentService.assignDirect(
            userId, fixture.roleAllowing(resource.requireId()).requireId(), fixture.orgScope(company, includeDescendants = false).requireId(),
        )

        assertEquals(Decision.ALLOW, decide(userId, resource.requireId(), orgId = company).decision)
        assertEquals(Decision.DENY, decide(userId, resource.requireId(), orgId = team).decision)
    }

    @Test
    fun `리소스 scope 는 상위 리소스로 지정하면 하위 리소스까지 덮는다`() {
        val clientId = fixture.client()
        val system = fixture.resource(clientId)
        val menu = fixture.resource(clientId, parentId = system.requireId())
        val userId = fixture.user()
        val role = fixture.roleAllowing(menu.requireId())
        assignmentService.assignDirect(userId, role.requireId(), fixture.resourceScope(system.requireId()).requireId())

        assertEquals(Decision.ALLOW, decide(userId, menu.requireId()).decision)
    }

    @Test
    fun `회수·만료된 할당과 비활성 역할·리소스는 판정에 쓰지 않는다`() {
        val resource = fixture.resource()

        val revokedUser = fixture.user()
        val revoked = assignmentService.assignDirect(revokedUser, fixture.roleAllowing(resource.requireId()).requireId())
        assignmentService.revoke(revoked.requireId())
        assertEquals(Decision.DENY, decide(revokedUser, resource.requireId()).decision)

        val expiredUser = fixture.user()
        assignmentService.assignDirect(
            expiredUser, fixture.roleAllowing(resource.requireId()).requireId(), validUntil = Instant.now().minusSeconds(1),
        )
        assertEquals(Decision.DENY, decide(expiredUser, resource.requireId()).decision)

        val inactiveRoleUser = fixture.user()
        val inactiveRole = fixture.roleAllowing(resource.requireId())
        assignmentService.assignDirect(inactiveRoleUser, inactiveRole.requireId())
        inactiveRole.deactivate()
        assertEquals(Decision.DENY, decide(inactiveRoleUser, resource.requireId()).decision)

        val activeUser = fixture.user()
        assignmentService.assignDirect(activeUser, fixture.roleAllowing(resource.requireId()).requireId())
        resource.deactivate()
        assertEquals(Decision.DENY, decide(activeUser, resource.requireId()).decision)
    }

    private fun decide(subjectId: Long, resourceId: Long, action: PermissionAction = PermissionAction.READ, orgId: Long? = null) =
        pdp.decide(AuthorizationRequest(subjectId, resourceId, action, orgId = orgId))
}
