package com.didrakon.iam.authz

import com.didrakon.iam.authz.assignment.AssignmentSourceType
import com.didrakon.iam.authz.assignment.AssignmentStatus
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignmentChangedEvent
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.assignment.RoleChangeType
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.identity.organization.OrgType
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.test.context.event.ApplicationEvents
import org.springframework.test.context.event.RecordApplicationEvents
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

@AuthzTest
@RecordApplicationEvents
class RoleAssignmentServiceTests @Autowired constructor(
    private val assignmentService: RoleAssignmentService,
    private val organizationRoleService: OrganizationRoleService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val fixture: AuthzFixture,
) {
    @Test
    fun `scope 를 지정하지 않은 직접 부여는 GLOBAL scope 로 만들어지고 변경 이벤트가 발행된다`(events: ApplicationEvents) {
        val userId = fixture.user()
        val role = fixture.role()

        val assignment = assignmentService.assignDirect(userId, role.requireId(), assignedBy = userId, reason = "업무 필요")

        assertEquals(fixture.globalScopeId(), assignment.scopeId)
        assertEquals(AssignmentSourceType.DIRECT, assignment.sourceType)
        val event = events.stream(RoleAssignmentChangedEvent::class.java).toList().single()
        assertEquals(RoleChangeType.ASSIGN, event.changeType)
        assertEquals(assignment.requireId(), event.assignmentId)
    }

    @Test
    fun `같은 역할·scope 로 중복 직접 부여할 수 없다`() {
        val userId = fixture.user()
        val roleId = fixture.role().requireId()
        assignmentService.assignDirect(userId, roleId)

        assertThrows<BusinessRuleException> { assignmentService.assignDirect(userId, roleId) }
    }

    @Test
    fun `비활성 역할은 부여할 수 없다`() {
        val role = fixture.role()
        role.deactivate()

        assertThrows<BusinessRuleException> { assignmentService.assignDirect(fixture.user(), role.requireId()) }
    }

    @Test
    fun `직접 부여를 회수하면 상태가 REVOKED 가 되고 회수자가 남는다`(events: ApplicationEvents) {
        val userId = fixture.user()
        val assignment = assignmentService.assignDirect(userId, fixture.role().requireId())

        assignmentService.revoke(assignment.requireId(), revokedBy = userId, reason = "퇴직")

        val revoked = assignmentRepository.findById(assignment.requireId()).orElseThrow()
        assertEquals(AssignmentStatus.REVOKED, revoked.status)
        assertEquals(userId, revoked.revokedBy)
        assertNotNull(revoked.revokedAt)
        assertEquals(RoleChangeType.REVOKE, events.stream(RoleAssignmentChangedEvent::class.java).toList().last().changeType)
    }

    @Test
    fun `조직 규칙으로 생긴 할당은 직접 회수할 수 없다`() {
        val userId = fixture.user()
        val orgId = fixture.org(OrgType.COMPANY)
        fixture.join(userId, orgId)
        organizationRoleService.create(orgId, fixture.role().requireId())
        val assignment = assignmentRepository.findActiveBySource(userId, AssignmentSourceType.ORGANIZATION).single()

        assertThrows<BusinessRuleException> { assignmentService.revoke(assignment.requireId()) }
    }
}
