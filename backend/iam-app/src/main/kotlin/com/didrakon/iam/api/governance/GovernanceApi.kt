package com.didrakon.iam.api.governance

import com.didrakon.iam.api.authz.IdResponse
import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.request.AccessRequest
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.sod.RoleConflictService
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

data class AccessRequestResponse(
    val requestId: Long,
    val requestType: String,
    val subjectId: Long,
    val roleId: Long,
    val scopeId: Long,
    val reason: String,
    val riskLevel: RiskLevel,
    val requestedStart: Instant,
    val requestedEnd: Instant,
    val status: String,
) {
    companion object {
        fun from(r: AccessRequest) = AccessRequestResponse(
            r.requireId(), r.requestType.name, r.subjectId, r.roleId, r.scopeId, r.reason, r.riskLevel, r.requestedStart, r.requestedEnd, r.status.name,
        )
    }
}

data class DecisionRequest(@field:Size(max = 1000) val comment: String? = null)

/** 승인자용. 본인 요청은 /me 아래에 있다 */
@RestController
@RequestMapping("/api/v1/access-requests")
class AccessRequestApi(private val accessRequestService: AccessRequestService, private val views: GovernanceViewService) {
    @GetMapping("/pending")
    @RequiresPermission(ApiResources.ACCESS_REQUEST, PermissionAction.READ)
    fun pending() = ApiResponse.ok(accessRequestService.pendingRequests().map(AccessRequestResponse::from))

    /** 처리가 끝난 요청(승인·반려·취소·만료) 최근 200건과 승인자 결정 */
    @GetMapping("/history")
    @RequiresPermission(ApiResources.ACCESS_REQUEST, PermissionAction.READ)
    fun history() = ApiResponse.ok(views.accessRequests(accessRequestService.history()))

    @PostMapping("/{requestId}/approve")
    @RequiresPermission(ApiResources.ACCESS_REQUEST, PermissionAction.APPROVE)
    fun approve(@PathVariable requestId: Long, @Valid @RequestBody r: DecisionRequest) =
        ApiResponse.ok(AccessRequestResponse.from(accessRequestService.approve(requestId, ApiPrincipal.requireSubjectId(), r.comment)))

    @PostMapping("/{requestId}/reject")
    @RequiresPermission(ApiResources.ACCESS_REQUEST, PermissionAction.APPROVE)
    fun reject(@PathVariable requestId: Long, @Valid @RequestBody r: DecisionRequest) =
        ApiResponse.ok(AccessRequestResponse.from(accessRequestService.reject(requestId, ApiPrincipal.requireSubjectId(), r.comment)))
}

data class DefineConflictRequest(val roleId1: Long, val roleId2: Long, val severity: RiskLevel, @field:Size(max = 1000) val description: String? = null)

data class ConflictExceptionRequest(val subjectId: Long, @field:NotBlank val reason: String, val validUntil: Instant? = null)

@RestController
@RequestMapping("/api/v1/role-conflicts")
class RoleConflictApi(private val conflictService: RoleConflictService) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.SOD, PermissionAction.CREATE)
    fun define(@Valid @RequestBody r: DefineConflictRequest) =
        ApiResponse.ok(IdResponse(conflictService.define(r.roleId1, r.roleId2, r.severity, r.description).requireId()))

    @PostMapping("/{conflictId}/exceptions")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.SOD, PermissionAction.APPROVE)
    fun grantException(@PathVariable conflictId: Long, @Valid @RequestBody r: ConflictExceptionRequest) = ApiResponse.ok(
        IdResponse(conflictService.grantException(conflictId, r.subjectId, ApiPrincipal.requireSubjectId(), r.reason, r.validUntil).requireId()),
    )
}

data class BreakGlassPolicyRequest(
    @field:NotBlank @field:Size(max = 200) val policyName: String,
    val roleId: Long,
    val scopeId: Long,
    val maxDurationMinutes: Int,
    val requireReason: Boolean = true,
    val requireApproval: Boolean = false,
    val requireMfa: Boolean = true,
    /** 시작할 수 있는 그룹. 비우면 누구나 */
    val eligibleGroupId: Long? = null,
)

/** 역할·범위는 바꾸지 않는다. 바꾸려면 새 정책을 만들고 이 정책을 끈다. eligibleGroupId 를 비우면 누구나 쓸 수 있게 된다 */
data class UpdateBreakGlassPolicyRequest(
    @field:NotBlank @field:Size(max = 200) val policyName: String,
    val maxDurationMinutes: Int,
    val requireReason: Boolean = true,
    val requireApproval: Boolean = false,
    val requireMfa: Boolean = true,
    val eligibleGroupId: Long? = null,
)

@RestController
@RequestMapping("/api/v1/break-glass-policies")
class BreakGlassPolicyApi(
    private val breakGlassService: BreakGlassService,
    private val views: GovernanceViewService,
    private val authorizer: AdminAuthorizer,
) {
    @GetMapping
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.READ)
    fun list() = ApiResponse.ok(views.breakGlassPolicies(breakGlassService.policies()))

    /** 대상 그룹 선택지 */
    @GetMapping("/group-options")
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.READ)
    fun groupOptions() = ApiResponse.ok(views.groupOptions())

    @PutMapping("/{policyId}")
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.UPDATE)
    fun update(@PathVariable policyId: Long, @Valid @RequestBody r: UpdateBreakGlassPolicyRequest): ApiResponse<Unit> {
        breakGlassService.policies().find { it.requireId() == policyId }?.let { authorizer.requireApprovalForConsoleRole(it.roleId, r.requireApproval) }
        breakGlassService.updatePolicy(policyId, r.policyName, r.maxDurationMinutes, r.requireReason, r.requireApproval, r.requireMfa, r.eligibleGroupId)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/{policyId}/activate")
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.UPDATE)
    fun activate(@PathVariable policyId: Long): ApiResponse<Unit> {
        // 꺼 둔 사이 역할에 관리 콘솔 권한이 생겼을 수 있다
        breakGlassService.policies().find { it.requireId() == policyId }?.let { authorizer.requireApprovalForConsoleRole(it.roleId, it.requireApproval) }
        breakGlassService.changePolicyActive(policyId, true)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/{policyId}/deactivate")
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.UPDATE)
    fun deactivate(@PathVariable policyId: Long): ApiResponse<Unit> {
        breakGlassService.changePolicyActive(policyId, false)
        return ApiResponse.ok(Unit)
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.CREATE)
    fun create(@Valid @RequestBody r: BreakGlassPolicyRequest): ApiResponse<IdResponse> {
        authorizer.requireApprovalForConsoleRole(r.roleId, r.requireApproval)
        return ApiResponse.ok(
            IdResponse(
                breakGlassService.createPolicy(
                    r.policyName, r.roleId, r.scopeId, r.maxDurationMinutes, r.requireReason, r.requireApproval, r.requireMfa, r.eligibleGroupId,
                ).requireId(),
            ),
        )
    }
}
