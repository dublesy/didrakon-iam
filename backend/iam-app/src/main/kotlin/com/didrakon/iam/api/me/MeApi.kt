package com.didrakon.iam.api.me

import com.didrakon.iam.api.authz.AssignmentResponse
import com.didrakon.iam.api.authz.IdResponse
import com.didrakon.iam.api.governance.AccessRequestResponse
import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiException
import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.SelfService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.mfa.MfaMethod
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.TotpEnrollment
import com.didrakon.iam.authn.passkey.Passkey
import com.didrakon.iam.authn.passkey.PasskeyService
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.OrgReach
import com.didrakon.iam.authz.decision.OrgReachService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.request.AccessRequestService
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

data class MeResponse(val subjectId: Long, val authenticationMethods: List<String>, val assignments: List<MeAssignmentResponse>)

/**
 * 본인 역할 할당 + 역할·범위 이름. 역할·범위 목록을 볼 권한이 없는 사람도 자기 역할 이름은 알아야 하므로 여기서 풀어 준다.
 * 앞쪽 필드는 [AssignmentResponse] 와 같다
 */
data class MeAssignmentResponse(
    val assignmentId: Long,
    val roleId: Long,
    val scopeId: Long,
    val sourceType: String,
    val sourceId: Long?,
    val validFrom: Instant,
    val validUntil: Instant?,
    val reviewRequired: Boolean,
    val roleCode: String?,
    val roleName: String?,
    val scopeCode: String?,
    val scopeName: String?,
)

/** 관리 리소스 하나에 대해 쓸 수 있는 행위 */
data class AdminResourceAccess(val resource: String, val actions: List<PermissionAction>)

/**
 * 관리 콘솔이 메뉴·화면 구성을 정할 때 쓰는 본인의 관리 범위. 실제 허용 여부는 API 마다 PDP 가 다시 판정한다.
 * - global: 쓸 수 있는 관리 권한이 하나 이상이고 모두 조직 제한이 없다
 * - orgIds: 조직 범위로 받은 권한이 닿는 조직 (하위 조직 포함)
 * - resources: 어느 범위에서든 쓸 수 있는 관리 리소스와 행위
 */
data class AdminScopeResponse(val global: Boolean, val orgIds: List<Long>, val resources: List<AdminResourceAccess>)

data class JitRequest(
    val roleId: Long,
    val scopeId: Long? = null,
    @field:NotBlank @field:Size(max = 1000) val reason: String,
    val requestedStart: Instant,
    val requestedEnd: Instant,
)

data class DelegateRequest(
    val delegateId: Long,
    val roleId: Long,
    val scopeId: Long,
    val startTime: Instant,
    val endTime: Instant,
    @field:NotBlank @field:Size(max = 1000) val reason: String,
)

data class BreakGlassRequest(val policyId: Long, @field:Size(max = 1000) val reason: String? = null)

/** 세션이 열렸으면 sessionId, 승인이 필요하면 requestId */
data class BreakGlassResponse(val sessionId: Long?, val endTime: Instant?, val pendingRequestId: Long?)

data class ChangeOwnPasswordRequest(@field:NotBlank val currentPassword: String, @field:NotBlank @field:Size(max = 200) val newPassword: String)

data class ConfirmTotpRequest(@field:Pattern(regexp = "\\d{6}") val code: String)

/** 등록된 2단계 인증 수단. 비밀값은 주지 않는다 */
data class MfaMethodResponse(val methodId: Long, val methodType: String, val registeredAt: Instant, val lastUsedAt: Instant?) {
    companion object {
        fun from(m: MfaMethod) = MfaMethodResponse(
            m.requireId(), m.methodType.name, m.registeredAt,
            // TOTP 시간 구간(30초) 번호를 그 구간의 시작 시각으로 바꾼다
            m.lastUsedStep?.let { Instant.ofEpochSecond(it * 30) },
        )
    }
}

/** 로그인한 본인의 일. 관리 권한 없이 쓸 수 있고, 대상은 항상 토큰의 subject 다 */
@RestController
@RequestMapping("/api/v1/me")
class MeApi(
    private val authorizer: AdminAuthorizer,
    private val reachService: OrgReachService,
    private val assignmentService: RoleAssignmentService,
    private val accessRequestService: AccessRequestService,
    private val delegationService: DelegationService,
    private val breakGlassService: BreakGlassService,
    private val mfaService: MfaService,
    private val accountService: LocalAccountService,
    private val passkeyService: PasskeyService,
    private val roleRepository: RoleRepository,
    private val scopeRepository: ScopeRepository,
) {
    @GetMapping
    @SelfService
    fun me(): ApiResponse<MeResponse> {
        val subjectId = ApiPrincipal.requireSubjectId()
        val assignments = assignmentService.effectiveAssignments(subjectId).map(AssignmentResponse::from)
        val roles = roleRepository.findAllById(assignments.map { it.roleId }.toSet()).associateBy { it.requireId() }
        val scopes = scopeRepository.findAllById(assignments.map { it.scopeId }.toSet()).associateBy { it.requireId() }
        return ApiResponse.ok(
            MeResponse(
                subjectId,
                ApiPrincipal.authenticationMethods(),
                assignments.map { a ->
                    MeAssignmentResponse(
                        a.assignmentId, a.roleId, a.scopeId, a.sourceType, a.sourceId, a.validFrom, a.validUntil, a.reviewRequired,
                        roles[a.roleId]?.roleCode, roles[a.roleId]?.roleName, scopes[a.scopeId]?.scopeCode, scopes[a.scopeId]?.scopeName,
                    )
                },
            ),
        )
    }

    @GetMapping("/admin-scope")
    @SelfService
    fun adminScope(): ApiResponse<AdminScopeResponse> {
        val targets = ApiResources.CATALOG.flatMap { (key, actions) -> actions.map { (key to it) } }
        val reach = reachService.reachAll(ApiPrincipal.requireSubjectId(), targets.map { (key, action) -> authorizer.resourceId(key) to action })
        val permitted = targets.associateWith { (key, action) -> reach.getValue(authorizer.resourceId(key) to action) }.filterValues { !it.isEmpty() }
        return ApiResponse.ok(
            AdminScopeResponse(
                global = permitted.isNotEmpty() && permitted.values.all { it is OrgReach.All },
                orgIds = permitted.values.filterIsInstance<OrgReach.Orgs>().flatMap { it.orgIds }.distinct().sorted(),
                resources = permitted.keys.groupBy({ it.first }, { it.second }).map { (key, actions) -> AdminResourceAccess(key, actions.sorted()) },
            ),
        )
    }

    @PostMapping("/access-requests")
    @ResponseStatus(HttpStatus.CREATED)
    @SelfService
    fun requestJit(@Valid @RequestBody r: JitRequest) = ApiResponse.ok(
        AccessRequestResponse.from(
            accessRequestService.requestJit(ApiPrincipal.requireSubjectId(), r.roleId, r.reason, r.requestedStart, r.requestedEnd, r.scopeId),
        ),
    )

    @PostMapping("/access-requests/{requestId}/cancel")
    @SelfService
    fun cancel(@PathVariable requestId: Long) =
        ApiResponse.ok(AccessRequestResponse.from(accessRequestService.cancel(requestId, ApiPrincipal.requireSubjectId())))

    @PostMapping("/delegations")
    @ResponseStatus(HttpStatus.CREATED)
    @SelfService
    fun delegate(@Valid @RequestBody r: DelegateRequest) = ApiResponse.ok(
        IdResponse(
            delegationService.delegate(requireDelegationLogin(r.roleId), r.delegateId, r.roleId, r.scopeId, r.startTime, r.endTime, r.reason).requireId(),
        ),
    )

    @DeleteMapping("/delegations/{delegationId}")
    @SelfService
    fun revokeDelegation(@PathVariable delegationId: Long, @RequestParam(required = false) reason: String?): ApiResponse<Unit> {
        delegationService.revokeAsDelegator(delegationId, ApiPrincipal.requireSubjectId(), reason)
        return ApiResponse.ok(Unit)
    }

    /** MFA 여부는 토큰의 amr 로 판단한다 (인증 앱 otp 또는 패스키 hwk) */
    @PostMapping("/break-glass")
    @SelfService
    fun breakGlass(@Valid @RequestBody r: BreakGlassRequest): ApiResponse<BreakGlassResponse> {
        val mfa = ApiPrincipal.authenticationMethods().any { it == "otp" || it == "hwk" }
        val activation = breakGlassService.activate(ApiPrincipal.requireSubjectId(), r.policyId, r.reason, mfa)
        return ApiResponse.ok(BreakGlassResponse(activation.session?.id, activation.session?.endTime, activation.pendingRequest?.id))
    }

    @PostMapping("/break-glass/{sessionId}/end")
    @SelfService
    fun endBreakGlass(@PathVariable sessionId: Long): ApiResponse<Unit> {
        breakGlassService.endOwn(sessionId, ApiPrincipal.requireSubjectId())
        return ApiResponse.ok(Unit)
    }

    /** 응답의 비밀값·otpauth URI 는 인증 앱 등록에만 쓰고 다시 조회할 수 없다 */
    @PostMapping("/mfa/totp")
    @ResponseStatus(HttpStatus.CREATED)
    @SelfService
    fun enrollTotp(): ApiResponse<TotpEnrollment> {
        val subjectId = requireFactorChange()
        // 인증 앱에 보이는 계정 이름. 로그인 ID 가 없으면 subject ID
        val label = accountService.findLocalIdentity(subjectId)?.externalId ?: subjectId.toString()
        return ApiResponse.ok(mfaService.enrollTotp(subjectId, label))
    }

    /** 본인 비밀번호 변경. 현재 비밀번호가 틀리면 로그인 실패와 같이 세어 잠근다 */
    @PostMapping("/password")
    @SelfService
    fun changePassword(@Valid @RequestBody r: ChangeOwnPasswordRequest): ApiResponse<Unit> {
        accountService.changeOwnPassword(ApiPrincipal.requireSubjectId(), r.currentPassword, r.newPassword)
        return ApiResponse.ok(Unit)
    }

    @GetMapping("/mfa")
    @SelfService
    fun mfaMethods() = ApiResponse.ok(mfaService.verifiedMethods(ApiPrincipal.requireSubjectId()).map(MfaMethodResponse::from))

    @PostMapping("/mfa/totp/{methodId}/confirm")
    @SelfService
    fun confirmTotp(@PathVariable methodId: Long, @Valid @RequestBody r: ConfirmTotpRequest): ApiResponse<Unit> {
        mfaService.confirmTotp(requireFactorChange(), methodId, r.code)
        return ApiResponse.ok(Unit)
    }

    @DeleteMapping("/mfa/{methodId}")
    @SelfService
    fun removeMfa(@PathVariable methodId: Long): ApiResponse<Unit> {
        mfaService.remove(requireFactorChange(), methodId)
        return ApiResponse.ok(Unit)
    }

    /** 등록한 패스키. 등록은 IAM 의 패스키 화면(/account/passkeys)에서 한다 */
    @GetMapping("/passkeys")
    @SelfService
    fun passkeys(): ApiResponse<List<Passkey>> = ApiResponse.ok(passkeyService.list(ApiPrincipal.requireSubjectId()))

    @DeleteMapping("/passkeys/{credentialId}")
    @SelfService
    fun removePasskey(@PathVariable credentialId: String): ApiResponse<Unit> {
        passkeyService.remove(requireFactorChange(), credentialId)
        return ApiResponse.ok(Unit)
    }

    /**
     * 2단계 인증 수단을 더하거나 지울 수 있는지 본다. 이 수단으로 비밀번호 재설정·로그인을 하므로 로그인 자체보다 약하면 안 된다.
     * - API 키로는 못 한다. 로그인한 사람의 토큰이어야 한다
     * - 이미 MFA 나 패스키가 있으면 MFA(otp) 또는 패스키(hwk)로 로그인한 토큰이어야 한다. 첫 등록은 비밀번호 로그인으로 한다
     */
    private fun requireFactorChange(): Long {
        val subjectId = ApiPrincipal.requireSubjectId()
        if (!ApiPrincipal.isJwt()) {
            throw ApiException(HttpStatus.FORBIDDEN, "INTERACTIVE_LOGIN_REQUIRED", "2단계 인증 수단은 로그인한 본인만 바꿀 수 있습니다 (API 키로는 안 됩니다)")
        }
        val hasFactor = mfaService.hasVerifiedMethod(subjectId) || passkeyService.list(subjectId).isNotEmpty()
        if (hasFactor && ApiPrincipal.authenticationMethods().none { it in STRONG_METHODS }) {
            throw ApiException(HttpStatus.UNAUTHORIZED, "MFA_REQUIRED", "2단계 인증 수단을 바꾸려면 MFA 로 다시 로그인하세요")
        }
        return subjectId
    }

    /**
     * 역할 위임은 로그인한 본인 토큰으로만 한다 (API 키로는 안 된다). 관리 콘솔 권한이 있는 역할은 MFA(otp) 또는 패스키(hwk)로 로그인한 토큰이어야 한다.
     * 관리 API MFA 정책에 막히는 자격 증명(API 키·비밀번호만 거친 토큰)으로 다른 계정에 관리 권한을 넘기지 못하게 한다
     */
    private fun requireDelegationLogin(roleId: Long): Long {
        val subjectId = ApiPrincipal.requireSubjectId()
        if (!ApiPrincipal.isJwt()) {
            throw ApiException(HttpStatus.FORBIDDEN, "INTERACTIVE_LOGIN_REQUIRED", "역할 위임은 로그인한 본인만 할 수 있습니다 (API 키로는 안 됩니다)")
        }
        if (authorizer.isConsoleRole(roleId) && ApiPrincipal.authenticationMethods().none { it in STRONG_METHODS }) {
            throw ApiException(HttpStatus.UNAUTHORIZED, "MFA_REQUIRED", "관리 권한이 있는 역할을 위임하려면 MFA 로 다시 로그인하세요")
        }
        return subjectId
    }

    companion object {
        private val STRONG_METHODS = setOf("otp", "hwk")
    }
}
