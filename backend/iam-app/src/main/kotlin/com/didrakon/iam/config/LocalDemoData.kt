package com.didrakon.iam.config

import com.didrakon.iam.identity.organization.OrganizationRepository
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authz.assignment.GroupRoleService
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.policy.PolicyTargetSpec
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.subject.UserService
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.core.annotation.Order
import org.springframework.core.Ordered
import org.springframework.stereotype.Component
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock
import java.time.Duration
import java.time.LocalDate

/**
 * 로컬에서 화면을 확인하기 위한 예시 데이터. `iam.demo-data.enabled=true` 일 때만 실행된다 (application-local.yml).
 * 업무 서비스를 그대로 불러 만들므로 조직·그룹 역할 자동 부여, 감사 기록, 위험 평가가 실제와 같이 일어난다.
 * 조직이 하나라도 있으면(이미 쓰는 DB) 아무것도 하지 않는다. 회사·사람은 가상이고 로그인 계정은 만들지 않는다.
 */
@Component
@Order(Ordered.LOWEST_PRECEDENCE)
@ConditionalOnProperty(prefix = "iam.demo-data", name = ["enabled"], havingValue = "true")
class LocalDemoData(
    private val transactionTemplate: TransactionTemplate,
    private val organizationRepository: OrganizationRepository,
    private val ssoClientService: SsoClientService,
    private val organizationService: OrganizationService,
    private val userService: UserService,
    private val membershipService: MembershipService,
    private val groupService: GroupService,
    private val groupRepository: UserGroupRepository,
    private val groupMemberService: GroupMemberService,
    private val catalogService: AuthzCatalogService,
    private val assignmentService: RoleAssignmentService,
    private val organizationRoleService: OrganizationRoleService,
    private val groupRoleService: GroupRoleService,
    private val policyService: PolicyService,
    private val policyVersionService: PolicyVersionService,
    private val conflictService: RoleConflictService,
    private val accessRequestService: AccessRequestService,
    private val clock: Clock,
) : ApplicationRunner {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun run(args: ApplicationArguments) {
        if (organizationRepository.count() > 0) return
        transactionTemplate.executeWithoutResult { create() }
        log.warn("로컬 예시 데이터를 만들었습니다 (조직·사용자·역할·ERP 리소스·대기 요청). 끄려면 iam.demo-data.enabled=false")
    }

    private fun create() {
        // 조직도
        val group = organizationService.create("NURI", "누리 그룹", OrgType.GROUP, null).requireId()
        val company = organizationService.create("NURI-CO", "누리케어", OrgType.COMPANY, group).requireId()
        val support = organizationService.create("DIV-SUPPORT", "경영지원본부", OrgType.DIVISION, company).requireId()
        val hr = organizationService.create("TEAM-HR", "인사팀", OrgType.TEAM, support).requireId()
        val finance = organizationService.create("TEAM-FIN", "재무팀", OrgType.TEAM, support).requireId()
        val service = organizationService.create("DIV-SERVICE", "서비스운영본부", OrgType.DIVISION, company).requireId()
        val gangnam = organizationService.create("CENTER-GANGNAM", "강남센터", OrgType.CENTER, service).requireId()
        val bundang = organizationService.create("CENTER-BUNDANG", "분당센터", OrgType.CENTER, service).requireId()
        val tech = organizationService.create("DIV-TECH", "기술본부", OrgType.DIVISION, company).requireId()
        val platform = organizationService.create("TEAM-PLATFORM", "플랫폼팀", OrgType.TEAM, tech).requireId()
        val data = organizationService.create("TEAM-DATA", "데이터팀", OrgType.TEAM, tech).requireId()

        // 사람 (이름은 가상)
        fun person(no: Int, name: String, orgId: Long, title: String, manager: Boolean = false): Long {
            val user = userService.create("D-%03d".format(no), name, "demo$no@example.com", null, LocalDate.of(2020 + no % 5, 1 + no % 12, 1))
            membershipService.join(user.requireId(), orgId, MembershipType.PRIMARY, jobTitle = title, isManager = manager)
            return user.requireId()
        }
        val hrLead = person(1, "김하늘", hr, "팀장", manager = true)
        person(2, "이서준", hr, "매니저")
        val finLead = person(3, "박지민", finance, "팀장", manager = true)
        val finClerk = person(4, "최유나", finance, "매니저")
        val finClerk2 = person(5, "정도윤", finance, "매니저")
        val gangnamLead = person(6, "강민서", gangnam, "센터장", manager = true)
        person(7, "윤채원", gangnam, "요양보호사")
        person(8, "임준호", bundang, "센터장", manager = true)
        person(9, "한소율", bundang, "사회복지사")
        val platformLead = person(10, "오세훈", platform, "팀장", manager = true)
        val engineer = person(11, "서지우", platform, "엔지니어")
        val analyst = person(12, "문가은", data, "분석가")
        membershipService.join(finLead, hr, MembershipType.SECONDARY, jobTitle = "겸직")

        // 업무 시스템과 리소스·권한
        val client = ssoClientService.register(
            ClientRegistration(
                CLIENT_CODE, "누리 ERP", ClientType.WEB,
                redirectUris = setOf("http://localhost:4000/callback"), postLogoutRedirectUris = setOf("http://localhost:4000/"),
            ),
        ).ssoClient.requireId()
        val erp = catalogService.createResource(client, "erp", "누리 ERP", ResourceType.SYSTEM, Sensitivity.INTERNAL).requireId()
        val payroll = catalogService.createResource(client, "erp.payroll", "급여", ResourceType.MENU, Sensitivity.CONFIDENTIAL, erp, "/payroll").requireId()
        val payment = catalogService.createResource(client, "erp.payment", "지급 요청", ResourceType.MENU, Sensitivity.INTERNAL, erp, "/payments").requireId()
        val careRecord = catalogService.createResource(client, "erp.care-record", "돌봄 기록", ResourceType.DATA, Sensitivity.CONFIDENTIAL, erp).requireId()
        val database = catalogService.createResource(client, "erp.db", "운영 DB", ResourceType.SYSTEM, Sensitivity.SECRET, erp).requireId()
        fun permission(resourceId: Long, key: String, name: String, action: PermissionAction) =
            catalogService.createPermission("$key:$action", name, resourceId, action, PermissionEffect.ALLOW).requireId()
        val payrollRead = permission(payroll, "erp.payroll", "급여 조회", PermissionAction.READ)
        val payrollUpdate = permission(payroll, "erp.payroll", "급여 변경", PermissionAction.UPDATE)
        val paymentCreate = permission(payment, "erp.payment", "지급 요청", PermissionAction.CREATE)
        val paymentApprove = permission(payment, "erp.payment", "지급 승인", PermissionAction.APPROVE)
        val careRead = permission(careRecord, "erp.care-record", "돌봄 기록 조회", PermissionAction.READ)
        val careUpdate = permission(careRecord, "erp.care-record", "돌봄 기록 작성", PermissionAction.UPDATE)
        val dbExecute = permission(database, "erp.db", "운영 DB 작업", PermissionAction.EXECUTE)

        // 역할
        fun role(code: String, name: String, type: RoleType, permissionIds: List<Long>, sensitive: Boolean = false, privileged: Boolean = false): Role =
            catalogService.createRole(code, name, type, sensitive, privileged, 0).also { r ->
                permissionIds.forEach { catalogService.grantPermission(r.requireId(), it) }
            }
        val hrManager = role("HR_MANAGER", "인사 관리자", RoleType.BUSINESS, listOf(payrollRead, payrollUpdate), sensitive = true)
        val paymentClerk = role("PAYMENT_CLERK", "지급 담당", RoleType.BUSINESS, listOf(paymentCreate))
        val paymentApprover = role("PAYMENT_APPROVER", "지급 승인자", RoleType.BUSINESS, listOf(paymentApprove), sensitive = true)
        val careStaff = role("CARE_STAFF", "센터 직원", RoleType.BUSINESS, listOf(careRead, careUpdate))
        val dbAdmin = role("DB_ADMIN", "운영 DB 관리자", RoleType.PRIVILEGED, listOf(dbExecute), sensitive = true, privileged = true)

        // 직무 분리: 지급을 요청한 사람이 스스로 승인하지 못하게
        conflictService.define(paymentClerk.requireId(), paymentApprover.requireId(), RiskLevel.HIGH, "지급 요청과 승인은 다른 사람이 한다")

        // 역할 부여 세 가지 경로: 직접, 조직 규칙, 그룹 규칙
        assignmentService.assignDirect(hrLead, hrManager.requireId(), reason = "인사팀장")
        assignmentService.assignDirect(finClerk, paymentClerk.requireId(), reason = "지급 업무 담당")
        assignmentService.assignDirect(finClerk2, paymentClerk.requireId(), reason = "지급 업무 담당")

        val serviceScope = catalogService.createScope("ORG-SERVICE", "서비스운영본부 전체", ScopeType.ORGANIZATION, orgId = service, includeDescendants = true)
        organizationRoleService.create(service, careStaff.requireId(), serviceScope.requireId(), applyToDescendants = true)

        val approvers = groupService.create("FIN-APPROVERS", "지급 결재라인", GroupType.STATIC, null).requireId()
        groupRoleService.create(approvers, paymentApprover.requireId())
        groupMemberService.addMember(approvers, finLead)
        groupMemberService.addMember(approvers, gangnamLead)

        val securityTeam = groupRepository.findByGroupCode(AccessRequestService.SECURITY_TEAM_GROUP)?.requireId()
            ?: groupService.create(AccessRequestService.SECURITY_TEAM_GROUP, "보안팀", GroupType.STATIC, null).requireId()
        groupMemberService.addMember(securityTeam, platformLead)

        // ABAC 정책: 돌봄 기록은 2단계 인증(인증 앱 또는 패스키)을 거친 로그인에서만
        val mfaPolicy = policyService.create(
            "ERP_CARE_RECORD_MFA", "돌봄 기록은 2단계 인증 필요", PolicyType.SECURITY, PolicyEffect.CHALLENGE,
            listOf(PolicyTargetSpec(resourceId = careRecord)),
        )
        val version = policyVersionService.createVersion(
            mfaPolicy.requireId(),
            listOf(RuleSpec(1, AttributeSource.SESSION, "amr", RuleOperator.NOT_IN, "[\"otp\",\"hwk\"]")),
            changeReason = "예시 데이터",
        )
        policyVersionService.activate(version.requireId())

        // 승인 대기 요청
        val now = clock.instant()
        accessRequestService.requestJit(engineer, dbAdmin.requireId(), "결제 장애 원인 확인을 위한 운영 DB 조회", now, now.plus(Duration.ofHours(4)))
        accessRequestService.requestJit(analyst, hrManager.requireId(), "분기 인력 현황 보고서 작성", now, now.plus(Duration.ofDays(3)))
    }

    companion object {
        const val CLIENT_CODE = "sample-erp"
    }
}
