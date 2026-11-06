package com.didrakon.iam.config

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.Policy
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.policy.PolicyRuleRepository
import com.didrakon.iam.authz.policy.PolicyTarget
import com.didrakon.iam.authz.policy.PolicyTargetRepository
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionRepository
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.PolicyVersionStatus
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.resource.Resource
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.role.Permission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RolePermission
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import org.slf4j.LoggerFactory
import org.springframework.boot.ApplicationArguments
import org.springframework.boot.ApplicationRunner
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.stereotype.Component
import org.springframework.transaction.support.TransactionTemplate
import java.time.Clock

/** 기동 시 초기 구성. application.yml 의 iam.bootstrap.* */
@ConfigurationProperties("iam.bootstrap")
data class BootstrapProperties(
    val adminConsoleRedirectUris: Set<String> = setOf("http://localhost:3000/callback"),
    /** 콘솔 로그아웃(/connect/logout) 후 돌아갈 주소 */
    val adminConsolePostLogoutRedirectUris: Set<String> = setOf("http://localhost:3000/"),
    /** IAM 관리 API 를 쓰는 역할(IAM_ADMIN·IAM_AUDITOR·IAM_ORG_ADMIN)에 MFA 를 요구하는 정책을 만든다 */
    val requireMfaForAdmin: Boolean = true,
    /** 비어 있지 않으면 최초 관리자 계정을 만든다. 비밀번호는 환경변수로만 넣고, 만든 뒤에는 바꾼다 */
    val adminLoginId: String = "",
    val adminPassword: String = "",
    val adminEmpNo: String = "IAM-ADMIN",
    val adminName: String = "IAM 관리자",
)

/**
 * IAM 이 자기 관리 API 를 자기 PDP 로 보호하는 데 필요한 데이터를 만든다. 여러 번 실행해도 결과가 같다.
 * - 관리 콘솔 SSO 클라이언트(iam-admin, PKCE public client)
 * - [ApiResources.CATALOG] 의 리소스·권한
 * - 역할: IAM_ADMIN(전체), IAM_AUDITOR(조회), IAM_ORG_ADMIN(조직 단위 관리자: 사람·소속·조직·세션, ORGANIZATION 범위로 할당),
 *   IAM_AUTHZ_CLIENT(권한 판정 API 호출용 서비스 계정), IAM_HR_SYNC(HR 연동 API 호출용 서비스 계정)
 * - IAM_ADMIN·IAM_AUDITOR·IAM_ORG_ADMIN 으로 허용된 요청에 MFA 를 요구하는 정책 (amr 에 otp(인증 앱)도 hwk(패스키)도 없으면 CHALLENGE)
 * - 최초 관리자 계정 (설정한 경우만)
 */
@Component
@EnableConfigurationProperties(BootstrapProperties::class)
class IamBootstrap(
    private val properties: BootstrapProperties,
    private val transactionTemplate: TransactionTemplate,
    private val ssoClientRepository: SsoClientRepository,
    private val ssoClientService: SsoClientService,
    private val resourceRepository: ResourceRepository,
    private val permissionRepository: PermissionRepository,
    private val roleRepository: RoleRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val scopeRepository: ScopeRepository,
    private val policyRepository: PolicyRepository,
    private val policyTargetRepository: PolicyTargetRepository,
    private val policyVersionService: PolicyVersionService,
    private val policyVersionRepository: PolicyVersionRepository,
    private val policyRuleRepository: PolicyRuleRepository,
    private val userRepository: UserRepository,
    private val accountService: LocalAccountService,
    private val assignmentService: RoleAssignmentService,
    private val clock: Clock,
) : ApplicationRunner {
    private val log = LoggerFactory.getLogger(javaClass)

    override fun run(args: ApplicationArguments) {
        transactionTemplate.executeWithoutResult {
            val clientId = adminClient()
            val permissions = catalog(clientId)
            val globalScopeId = scopeRepository.findByScopeCode(Scope.GLOBAL_CODE)?.requireId()
                ?: throw IllegalStateException("GLOBAL scope 행이 없습니다")
            val admin = role(ADMIN_ROLE, "IAM 관리자", RoleType.PRIVILEGED, permissions.values, globalScopeId)
            val auditor = role(AUDITOR_ROLE, "IAM 감사자", RoleType.SYSTEM, permissions.filterKeys { it.second == PermissionAction.READ }.values, globalScopeId)
            val orgAdmin = role(ORG_ADMIN_ROLE, "조직 단위 관리자", RoleType.SYSTEM, ORG_ADMIN_PERMISSIONS.mapNotNull { permissions[it] }, globalScopeId)
            role(AUTHZ_CLIENT_ROLE, "권한 판정 API 호출", RoleType.SYSTEM, listOfNotNull(permissions[ApiResources.AUTHZ_CHECK to PermissionAction.EXECUTE]), globalScopeId)
            role(HR_SYNC_ROLE, "HR 연동 API 호출", RoleType.SYSTEM, permissions.filterKeys { it.first == ApiResources.HR_SYNC }.values, globalScopeId)
            if (properties.requireMfaForAdmin) mfaPolicy(listOf(admin, auditor, orgAdmin))
            bootstrapAdmin(admin)
        }
    }

    private fun adminClient(): Long =
        ssoClientRepository.findByClientCode(ApiResources.CLIENT_CODE)?.requireId()
            ?: ssoClientService.register(
                ClientRegistration(
                    clientCode = ApiResources.CLIENT_CODE,
                    clientName = "IAM 관리 콘솔",
                    clientType = ClientType.WEB,
                    redirectUris = properties.adminConsoleRedirectUris,
                    postLogoutRedirectUris = properties.adminConsolePostLogoutRedirectUris,
                    confidential = false,
                ),
            ).ssoClient.requireId()

    /** (리소스 키, 행위) → 권한 */
    private fun catalog(clientId: Long): Map<Pair<String, PermissionAction>, Permission> {
        val root = resourceRepository.findByClientIdAndResourceKey(clientId, ApiResources.ROOT)
            ?: resourceRepository.save(Resource(clientId, ApiResources.ROOT, "IAM 관리 API", ResourceType.SYSTEM, Sensitivity.CONFIDENTIAL))
        return ApiResources.CATALOG.flatMap { (key, actions) ->
            val resource = resourceRepository.findByClientIdAndResourceKey(clientId, key)
                ?: resourceRepository.save(Resource(clientId, key, key, ResourceType.API, Sensitivity.CONFIDENTIAL, root.requireId()))
            actions.map { action ->
                val existing = permissionRepository.findByResourceIdAndActionAndIsActiveTrue(resource.requireId(), action).firstOrNull()
                (key to action) to (
                    existing ?: permissionRepository.save(
                        Permission(ApiResources.permissionCode(key, action), "$key $action", resource.requireId(), action),
                    )
                    )
            }
        }.toMap()
    }

    private fun role(code: String, name: String, type: RoleType, permissions: Collection<Permission>, scopeId: Long): Role {
        val role = roleRepository.findByRoleCode(code)
            ?: roleRepository.save(Role(code, name, type, isSensitive = true, isPrivileged = type == RoleType.PRIVILEGED))
        val granted = rolePermissionRepository.findEffective(listOf(role.requireId()), permissions.map { it.requireId() }, clock.instant())
            .map { it.permissionId }.toSet()
        permissions.filter { it.requireId() !in granted }.forEach {
            rolePermissionRepository.save(RolePermission(role.requireId(), it.requireId(), scopeId, clock.instant()))
        }
        return role
    }

    /** 정책이 이미 있으면 빠진 역할 대상만 더한다 (나중에 생긴 역할도 MFA 를 요구받도록) */
    private fun mfaPolicy(roles: List<Role>) {
        policyRepository.findAll().firstOrNull { it.policyCode == MFA_POLICY }?.let { existing ->
            val targeted = policyTargetRepository.findByPolicyId(existing.requireId()).mapNotNull { it.roleId }.toSet()
            roles.filter { it.requireId() !in targeted }.forEach { policyTargetRepository.save(PolicyTarget.role(existing.requireId(), it.requireId())) }
            acceptPasskey(existing.requireId())
            return
        }
        val policy = policyRepository.save(Policy(MFA_POLICY, "IAM 관리 API MFA 필수", PolicyType.SECURITY, PolicyEffect.CHALLENGE))
        roles.forEach { policyTargetRepository.save(PolicyTarget.role(policy.requireId(), it.requireId())) }
        val version = policyVersionService.createVersion(policy.requireId(), listOf(MFA_RULE), changeReason = "초기 구성")
        policyVersionService.activate(version.requireId())
    }

    /**
     * 패스키 이전에 만든 정책(amr NOT_IN ["otp"])이면 패스키(hwk)도 MFA 로 인정하는 새 버전을 만들어 활성화한다.
     * 버전으로 바꿔 정책 변경 이력이 남는다. 관리자가 규칙을 이미 고쳤으면 건드리지 않는다
     */
    private fun acceptPasskey(policyId: Long) {
        val active = policyVersionRepository.findByPolicyIdAndStatus(policyId, PolicyVersionStatus.ACTIVE).singleOrNull() ?: return
        val rules = policyRuleRepository.findByPolicyVersionIdIn(listOf(active.requireId()))
        val beforePasskey = rules.singleOrNull()?.takeIf {
            it.attributeSource == AttributeSource.SESSION && it.attributeName == "amr" && it.operator == RuleOperator.NOT_IN &&
                it.attributeValue == OTP_ONLY_VALUE
        }
        if (beforePasskey == null) return
        val version = policyVersionService.createVersion(policyId, listOf(MFA_RULE), changeReason = "패스키(hwk) 로그인도 MFA 로 인정")
        policyVersionService.activate(version.requireId())
    }

    private fun bootstrapAdmin(adminRole: Role) {
        if (properties.adminLoginId.isBlank()) return
        if (accountService.findIdentity(properties.adminLoginId) != null) return
        if (properties.adminPassword.isBlank()) throw IllegalStateException("iam.bootstrap.admin-password 가 필요합니다")
        val user = userRepository.findByEmpNo(properties.adminEmpNo) ?: userRepository.save(User(properties.adminEmpNo, properties.adminName))
        accountService.createAccount(user.requireId(), properties.adminLoginId, properties.adminPassword)
        assignmentService.assignDirect(user.requireId(), adminRole.requireId(), reason = "초기 관리자")
        log.warn("초기 관리자 계정을 만들었습니다: {}. 로그인 후 비밀번호를 바꾸고 MFA 를 등록하세요", properties.adminLoginId)
    }

    companion object {
        const val ADMIN_ROLE = "IAM_ADMIN"
        const val AUDITOR_ROLE = "IAM_AUDITOR"
        const val AUTHZ_CLIENT_ROLE = "IAM_AUTHZ_CLIENT"
        const val HR_SYNC_ROLE = "IAM_HR_SYNC"
        const val ORG_ADMIN_ROLE = "IAM_ORG_ADMIN"

        /**
         * 조직 단위 관리자가 받는 권한: 사람·소속·조직·로그인 세션만. ORGANIZATION 범위 할당으로 줘야 그 조직(과 하위)에만 통한다.
         * 역할·할당·정책·리소스·클라이언트·위험·webhook·재검토·HR 연동 권한은 넣지 않는다 (스스로 권한을 넓히지 못하게)
         */
        val ORG_ADMIN_PERMISSIONS: List<Pair<String, PermissionAction>> = listOf(
            ApiResources.USER to PermissionAction.READ,
            ApiResources.USER to PermissionAction.CREATE,
            ApiResources.USER to PermissionAction.UPDATE,
            ApiResources.MEMBERSHIP to PermissionAction.READ,
            ApiResources.MEMBERSHIP to PermissionAction.CREATE,
            ApiResources.MEMBERSHIP to PermissionAction.UPDATE,
            ApiResources.MEMBERSHIP to PermissionAction.DELETE,
            ApiResources.ORGANIZATION to PermissionAction.READ,
            ApiResources.ORGANIZATION to PermissionAction.UPDATE,
            ApiResources.SESSION to PermissionAction.READ,
            ApiResources.SESSION to PermissionAction.DELETE,
        )
        const val MFA_POLICY = "IAM_ADMIN_API_MFA"

        /** 인증 앱(otp)도 패스키(hwk)도 거치지 않은 로그인이면 CHALLENGE */
        val MFA_RULE = RuleSpec(1, AttributeSource.SESSION, "amr", RuleOperator.NOT_IN, "[\"otp\",\"hwk\"]")
        private const val OTP_ONLY_VALUE = "[\"otp\"]"
    }
}
