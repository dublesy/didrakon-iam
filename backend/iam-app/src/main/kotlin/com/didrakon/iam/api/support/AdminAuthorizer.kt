package com.didrakon.iam.api.support

import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.session.LoginSessionRepository
import com.didrakon.iam.authz.assignment.GroupRoleRepository
import com.didrakon.iam.authz.assignment.OrganizationRoleRepository
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.Decision
import com.didrakon.iam.authz.decision.OrgReach
import com.didrakon.iam.authz.decision.OrgReachService
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.policy.PolicyRepository
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.common.context.RequestContextHolder
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.governance.breakglass.BreakGlassPolicyRepository
import com.didrakon.iam.governance.request.ConsoleRoles
import com.didrakon.iam.governance.review.ConsoleAdministrators
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import org.slf4j.LoggerFactory
import org.springframework.data.repository.findByIdOrNull
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Component
import java.time.Clock
import java.util.concurrent.ConcurrentHashMap

/**
 * 관리 API 의 대상. 판정할 때 PDP 에 넘길 대상 조직(orgId)을 경로 변수에서 찾는다.
 * ORGANIZATION 범위로 받은 권한(조직 단위 관리자)은 대상 조직이 그 범위 안일 때만 맞는다. 대상 조직이 없으면 전체(GLOBAL) 범위 권한만 통과한다.
 */
enum class OrgTarget(val pathVariable: String?) {
    /** 조직과 무관한 API (역할·정책·리소스 등). 전체 범위 권한만 통과한다 */
    NONE(null),

    /** 경로의 subjectId → 그 사람의 활성 PRIMARY 소속 조직 (없으면 다른 활성 소속 중 하나, 그것도 없으면 대상 조직 없음) */
    SUBJECT("subjectId"),

    /** 경로의 orgId → 그 조직 */
    ORG("orgId"),

    /** 경로의 membershipId → 그 소속의 조직 */
    MEMBERSHIP("membershipId"),

    /** 경로의 sessionId → 그 로그인 세션 주인의 조직 (SUBJECT 와 같은 규칙) */
    SESSION("sessionId"),

    /**
     * 어느 조직에서든 권한이 있으면 통과한다. 목록은 핸들러가 [AdminAuthorizer.reach] 로 거르고,
     * 본문으로 받은 조직·사용자는 핸들러가 [AdminAuthorizer.requireOrg]·[AdminAuthorizer.requireSubject] 로 다시 확인해야 한다
     */
    ANY(null),
}

/**
 * 관리 API 인가. [PermissionInterceptor] 와, 본문으로 대상을 받는 핸들러가 함께 쓴다.
 * 판정은 언제나 IAM 자신의 PDP 로 한다 (RBAC + MFA 같은 ABAC 정책까지).
 */
@Component
class AdminAuthorizer(
    private val pdp: PolicyDecisionPoint,
    private val reachService: OrgReachService,
    private val ssoClientRepository: SsoClientRepository,
    private val resourceRepository: ResourceRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val sessionRepository: LoginSessionRepository,
    private val subjectRepository: SubjectRepository,
    private val permissionRepository: PermissionRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val organizationRoleRepository: OrganizationRoleRepository,
    private val groupRoleRepository: GroupRoleRepository,
    private val policyRepository: PolicyRepository,
    private val breakGlassPolicyRepository: BreakGlassPolicyRepository,
    private val clock: Clock,
) : ConsoleAdministrators, ConsoleRoles {
    private val log = LoggerFactory.getLogger(javaClass)
    private val resourceIds = ConcurrentHashMap<String, Long>()

    /** IAM 관리 API 리소스 전체. 이 중 하나라도 권한이 있으면 "관리자"로 본다 */
    private val consoleResourceIds: Set<Long> by lazy { resourceRepository.findByClientId(consoleClientId()).map { it.requireId() }.toSet() }

    /** 대상 조직을 넣어 PDP 로 판정한다. 허용이 아니면 예외 */
    fun authorize(resourceKey: String, action: PermissionAction, orgId: Long?, ipAddress: String?) {
        val subjectId = ApiPrincipal.requireSubjectId()
        val result = pdp.decide(
            AuthorizationRequest(
                subjectId = subjectId,
                resourceId = resourceId(resourceKey),
                action = action,
                orgId = orgId,
                // 위험 평가는 ip 를, ABAC 규칙은 예전부터 ipAddress 를 읽으므로 둘 다 넣는다
                context = mapOf("ip" to ipAddress, "ipAddress" to ipAddress),
                session = mapOf("amr" to ApiPrincipal.authenticationMethods()),
                traceId = RequestContextHolder.current()?.traceId,
            ),
        )
        when (result.decision) {
            Decision.ALLOW -> return
            Decision.CHALLENGE -> throw ApiException(HttpStatus.UNAUTHORIZED, "MFA_REQUIRED", "MFA 를 거친 로그인이 필요합니다")
            Decision.REQUIRE_APPROVAL -> throw ApiException(HttpStatus.FORBIDDEN, "APPROVAL_REQUIRED", "승인을 받은 뒤 사용할 수 있습니다")
            Decision.DENY -> {
                // 판정 사유는 판정 로그에 남고, 응답에는 내부 구성을 드러내지 않는다
                log.debug("관리 API 거부: subject={}, {}:{} org={} - {}", subjectId, resourceKey, action, orgId, result.reason)
                throw forbidden()
            }
        }
    }

    /** 로그인한 사람의 (리소스, 행위) 권한이 닿는 조직 */
    fun reach(resourceKey: String, action: PermissionAction): OrgReach =
        reachService.reach(ApiPrincipal.requireSubjectId(), resourceId(resourceKey), action)

    /** 본문으로 받은 대상 조직이 권한 범위 안인지 확인한다. null 이면 전체 범위 권한이 있어야 한다 */
    fun requireOrg(resourceKey: String, action: PermissionAction, orgId: Long?) =
        authorize(resourceKey, action, orgId, RequestContextHolder.current()?.ipAddress)

    /** 본문으로 받은 대상 사용자가 권한 범위 안인지 확인한다 ([OrgTarget.SUBJECT] 와 같은 규칙) */
    fun requireSubject(resourceKey: String, action: PermissionAction, subjectId: Long) {
        requireOrg(resourceKey, action, orgOfSubject(subjectId))
        guardAdminTarget(resourceKey, action, subjectId)
    }

    /** 경로 변수로 대상 (조직, 대상 사용자) 를 찾는다. 값이 없거나 대상이 없으면 null */
    fun resolve(target: OrgTarget, pathValue: Long?): ResolvedTarget {
        if (pathValue == null) return ResolvedTarget(null, null)
        return when (target) {
            OrgTarget.NONE, OrgTarget.ANY -> ResolvedTarget(null, null)
            OrgTarget.SUBJECT -> ResolvedTarget(orgOfSubject(pathValue), pathValue)
            OrgTarget.ORG -> ResolvedTarget(pathValue, null)
            OrgTarget.MEMBERSHIP -> membershipRepository.findByIdOrNull(pathValue)
                ?.let { ResolvedTarget(it.orgId, it.subjectId) } ?: ResolvedTarget(null, null)
            OrgTarget.SESSION -> sessionRepository.findByIdOrNull(pathValue)
                ?.let { ResolvedTarget(orgOfSubject(it.subjectId), it.subjectId) } ?: ResolvedTarget(null, null)
        }
    }

    /** 사람의 대표 조직: 활성 PRIMARY 소속, 없으면 가장 먼저 만든 활성 소속 */
    fun orgOfSubject(subjectId: Long): Long? =
        membershipRepository.findActivePrimary(subjectId)?.orgId
            ?: membershipRepository.findActiveBySubjectId(subjectId).minByOrNull { it.requireId() }?.orgId

    /**
     * 조직 단위 관리자는 IAM 관리 권한을 가진 사람(다른 관리자)을 바꿀 수 없다.
     * 같은 조직에 있는 전체 관리자의 비밀번호를 초기화하거나 사용 중지하는 식의 권한 상승·무력화를 막는다. 조회는 막지 않는다
     */
    fun guardAdminTarget(resourceKey: String, action: PermissionAction, targetSubjectId: Long) {
        if (action == PermissionAction.READ) return
        if (reach(resourceKey, action) is OrgReach.All) return
        if (targetSubjectId == ApiPrincipal.subjectId()) return
        if (reachService.holdsPermissionOn(targetSubjectId, consoleResourceIds)) {
            log.debug("조직 단위 관리자가 관리자를 바꾸려 함: target={}, {}:{}", targetSubjectId, resourceKey, action)
            throw forbidden()
        }
    }

    /** 관리 콘솔 권한을 가졌거나 곧 받을 사람 (접근 재검토에서 조직장 대신 관리자가 검토할 대상) */
    override fun isAdministrator(subjectId: Long): Boolean = reachService.holdsPermissionOn(subjectId, consoleResourceIds)

    /**
     * 본인 API(@SelfService)는 사용 중인 사람만 쓴다. 사용 중지·잠김·퇴사한 사람의 남은 접근 토큰(최대 10분)으로
     * 위임·비상 접근·인증 수단 변경을 하지 못하게 한다 (관리 API 는 PDP 가 같은 검사를 한다)
     */
    fun requireActiveSubject(subjectId: Long) {
        if (subjectRepository.findByIdOrNull(subjectId)?.status != SubjectStatus.ACTIVE) {
            throw ApiException(HttpStatus.FORBIDDEN, "SUBJECT_INACTIVE", "사용 중인 계정만 쓸 수 있습니다")
        }
    }

    /**
     * 관리 콘솔 권한이 있는 역할은 직접 할당만 한다. 조직·그룹 역할 규칙으로 주면, 소속을 바꿀 수 있는
     * 조직 단위 관리자가 자기나 다른 사람을 그 조직에 넣어 관리 역할을 얻는다 (조직 단위 관리자는 역할을 줄 수 없다)
     */
    fun requireNotConsoleRole(roleId: Long) {
        if (isConsoleRole(roleId)) {
            throw BusinessRuleException("관리 콘솔 권한이 있는 역할은 조직·그룹 역할 규칙으로 줄 수 없습니다. 사람에게 직접 할당하세요")
        }
    }

    /**
     * 비상 접근 정책은 사용 중인 사람이면 누구나 시작할 수 있다. 관리 콘솔 권한이 있는 역할을 주는 정책은
     * 다른 사람의 승인을 거치게 해, MFA 만 있으면 누구나 관리자가 되는 일을 막는다
     */
    fun requireApprovalForConsoleRole(roleId: Long, requireApproval: Boolean) {
        if (!requireApproval && isConsoleRole(roleId)) {
            throw BusinessRuleException("관리 콘솔 권한이 있는 역할의 비상 접근은 승인 후 시작으로 해야 합니다")
        }
    }

    /**
     * 관리 API MFA 정책(IamBootstrap.MFA_POLICY)은 콘솔에서 끄거나 대상·규칙을 바꾸지 않는다.
     * 관리자 보호의 바탕이라 끄면 비밀번호만으로 관리 API 를 쓰게 되고, 대상은 기동할 때 다시 붙어 바꿔도 소용없다.
     * 켜고 끄기는 설정(iam.bootstrap.require-mfa-for-admin)으로 한다
     */
    fun requireEditablePolicy(policyId: Long) {
        if (policyRepository.findByIdOrNull(policyId)?.policyCode == IamBootstrap.MFA_POLICY) {
            throw BusinessRuleException("관리 API MFA 정책은 콘솔에서 끄거나 대상·규칙을 바꿀 수 없습니다. 설정으로 관리합니다")
        }
    }

    /** 역할에 지금 유효한 IAM 관리 리소스 권한이 있는지 */
    override fun isConsoleRole(roleId: Long): Boolean {
        val now = clock.instant()
        val permissionIds = rolePermissionRepository.findByRoleId(roleId)
            .filter { it.validUntil?.isAfter(now) ?: true }.map { it.permissionId }
        return permissionRepository.findAllById(permissionIds).any { it.resourceId in consoleResourceIds }
    }

    /**
     * 조직·그룹 역할 규칙에 쓰는 역할에는 관리 콘솔 권한을 더하지 않는다 ([requireNotConsoleRole] 과 같은 이유).
     * 승인 없이 시작하는 비상 접근 정책이 주는 역할도 마찬가지다 ([requireApprovalForConsoleRole] 과 같은 이유)
     */
    fun requirePermissionAllowedForRole(roleId: Long, permissionId: Long) {
        val permission = permissionRepository.findByIdOrNull(permissionId) ?: return
        if (permission.resourceId !in consoleResourceIds) return
        if (organizationRoleRepository.existsByRoleIdAndIsActiveTrue(roleId) || groupRoleRepository.existsByRoleId(roleId)) {
            throw BusinessRuleException("조직·그룹 역할 규칙에 쓰는 역할에는 관리 콘솔 권한을 더할 수 없습니다")
        }
        if (breakGlassPolicyRepository.existsByRoleIdAndRequireApprovalFalse(roleId)) {
            throw BusinessRuleException("승인 없이 시작하는 비상 접근 정책이 주는 역할에는 관리 콘솔 권한을 더할 수 없습니다. 정책을 승인 후 시작으로 바꾸세요")
        }
    }

    fun resourceId(resourceKey: String): Long = resourceIds.getOrPut(resourceKey) {
        resourceRepository.findByClientIdAndResourceKey(consoleClientId(), resourceKey)?.requireId()
            ?: throw IllegalStateException("IAM 관리 리소스가 없습니다: $resourceKey")
    }

    private fun consoleClientId(): Long = ssoClientRepository.findByClientCode(ApiResources.CLIENT_CODE)?.requireId()
        ?: throw IllegalStateException("IAM 관리 클라이언트가 없습니다 (IamBootstrap 확인)")

    private fun forbidden() = ApiException(HttpStatus.FORBIDDEN, "FORBIDDEN", "권한이 없습니다")
}

/** 판정 대상 조직과, 대상이 사람이면 그 subject */
data class ResolvedTarget(val orgId: Long?, val subjectId: Long?)
