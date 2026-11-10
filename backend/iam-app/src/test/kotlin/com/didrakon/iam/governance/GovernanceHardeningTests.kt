package com.didrakon.iam.governance

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.request.AccessRequestRepository
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.request.AccessRequestStatus
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 퇴사·승인·직무 분리 운영 보강. 테스트마다 롤백된다 */
@AuthzTest
class GovernanceHardeningTests @Autowired constructor(
    private val accessRequestService: AccessRequestService,
    private val accessRequestRepository: AccessRequestRepository,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val delegationService: DelegationService,
    private val conflictService: RoleConflictService,
    private val userService: UserService,
    private val catalogService: AuthzCatalogService,
    private val permissionRepository: PermissionRepository,
    private val authorizer: AdminAuthorizer,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    private val now: Instant get() = Instant.now()

    @Test
    fun `퇴사하면 앞으로 시작할 위임도 회수하고 처리 중인 권한 요청은 취소한다`() {
        val role = fixture.role().requireId()
        val delegator = fixture.user().also { assignmentService.assignDirect(it, role) }
        val leaver = fixture.user()
        delegationService.delegate(delegator, leaver, role, fixture.globalScopeId(), now.plusSeconds(3600), now.plusSeconds(7200), "휴가")
        val request = accessRequestService.requestJit(leaver, fixture.role().requireId(), "점검", now, now.plusSeconds(3600))

        userService.retire(leaver, null)

        assertTrue(assignmentRepository.findCurrentOrUpcoming(leaver, now).isEmpty(), "시작 전인 위임 할당도 남지 않는다")
        assertEquals(AccessRequestStatus.CANCELLED, accessRequestRepository.findById(request.requireId()).orElseThrow().status)
    }

    @Test
    fun `사용 중이 아닌 사람의 요청은 승인할 수 없다`() {
        val requester = fixture.user()
        val request = accessRequestService.requestJit(requester, fixture.role().requireId(), "점검", now, now.plusSeconds(3600))
        userService.changeStatus(requester, SubjectStatus.DISABLED)

        assertThrows<BusinessRuleException> { accessRequestService.approve(request.requireId(), fixture.user()) }
    }

    @Test
    fun `관리 콘솔 권한이 있는 역할의 요청은 서로 다른 승인자 2명이 승인해야 한다`() {
        val consoleRole = fixture.role().requireId()
        val permission = permissionRepository
            .findByResourceIdAndActionAndIsActiveTrue(authorizer.resourceId(ApiResources.USER), PermissionAction.READ).first().requireId()
        catalogService.grantPermission(consoleRole, permission)
        val requester = fixture.user()
        val request = accessRequestService.requestJit(requester, consoleRole, "장애 조사", now, now.plusSeconds(3600))

        assertEquals(AccessRequestStatus.PENDING, accessRequestService.approve(request.requireId(), fixture.user()).status)
        assertEquals(AccessRequestStatus.APPROVED, accessRequestService.approve(request.requireId(), fixture.user()).status)

        // 관리 권한이 없는 역할은 지금처럼 한 명이면 된다
        val plain = accessRequestService.requestJit(fixture.user(), fixture.role().requireId(), "점검", now, now.plusSeconds(3600))
        assertEquals(AccessRequestStatus.APPROVED, accessRequestService.approve(plain.requireId(), fixture.user()).status)
    }

    @Test
    fun `직무 분리 규칙을 만들거나 예외를 주면 감사 기록에 남는다`() {
        val conflict = conflictService.define(fixture.role().requireId(), fixture.role().requireId(), RiskLevel.HIGH)
        conflictService.grantException(conflict.requireId(), fixture.user(), fixture.user(), "결산 기간", now.plusSeconds(3600))

        val actions = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'ROLE_CONFLICT' AND resource_id = ? ORDER BY event_id",
            String::class.java, conflict.requireId().toString(),
        )
        assertEquals(listOf("CREATE", "ADD_EXCEPTION"), actions)
    }
}
