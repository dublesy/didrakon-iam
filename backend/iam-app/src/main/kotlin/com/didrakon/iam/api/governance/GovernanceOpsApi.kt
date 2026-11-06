package com.didrakon.iam.api.governance

import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.api.support.SelfService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.request.AccessRequestService
import jakarta.validation.Valid
import jakarta.validation.constraints.Size
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.RestController

data class EndReasonRequest(@field:Size(max = 1000) val reason: String? = null)

/** 비상 접근 세션 운영. 관리자가 진행 중인 세션을 끝내면 그 세션으로 받은 역할이 바로 회수된다 */
@RestController
@RequestMapping("/api/v1/break-glass-sessions")
class BreakGlassSessionApi(private val breakGlassService: BreakGlassService, private val views: GovernanceViewService) {
    /** 진행 중인 세션 전부와 최근 세션 100건 */
    @GetMapping
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.READ)
    fun list() = ApiResponse.ok(views.breakGlassSessions(breakGlassService.sessions()))

    @PostMapping("/{sessionId}/end")
    @RequiresPermission(ApiResources.BREAK_GLASS, PermissionAction.UPDATE)
    fun end(@PathVariable sessionId: Long): ApiResponse<Unit> {
        breakGlassService.end(sessionId, ApiPrincipal.requireSubjectId())
        return ApiResponse.ok(Unit)
    }
}

/** 위임 운영. 관리자가 회수하면 대리인의 위임 할당도 바로 회수된다 */
@RestController
@RequestMapping("/api/v1/delegations")
class DelegationApi(private val delegationService: DelegationService, private val views: GovernanceViewService) {
    /** 진행 중·시작 전 위임 전부와 최근 위임 200건 */
    @GetMapping
    @RequiresPermission(ApiResources.DELEGATION, PermissionAction.READ)
    fun list() = ApiResponse.ok(views.delegations(delegationService.delegations()))

    @PostMapping("/{delegationId}/revoke")
    @RequiresPermission(ApiResources.DELEGATION, PermissionAction.UPDATE)
    fun revoke(@PathVariable delegationId: Long, @Valid @RequestBody r: EndReasonRequest): ApiResponse<Unit> {
        delegationService.revoke(delegationId, ApiPrincipal.requireSubjectId(), r.reason?.trim()?.ifBlank { null } ?: "관리자 회수")
        return ApiResponse.ok(Unit)
    }
}

/** 본인의 권한 요청·위임·비상 접근 조회. 요청·취소·위임·시작·종료는 MeApi 에 있다. 대상은 항상 토큰의 subject 다 */
@RestController
@RequestMapping("/api/v1/me")
class MeGovernanceApi(
    private val accessRequestService: AccessRequestService,
    private val delegationService: DelegationService,
    private val breakGlassService: BreakGlassService,
    private val views: GovernanceViewService,
) {
    @GetMapping("/access-requests")
    @SelfService
    fun accessRequests() = ApiResponse.ok(views.accessRequests(accessRequestService.requestsOf(ApiPrincipal.requireSubjectId())))

    @GetMapping("/delegations")
    @SelfService
    fun delegations(): ApiResponse<MyDelegationsResponse> {
        val subjectId = ApiPrincipal.requireSubjectId()
        val all = views.delegations(delegationService.delegationsOf(subjectId))
        return ApiResponse.ok(MyDelegationsResponse(all.filter { it.delegatorId == subjectId }, all.filter { it.delegateId == subjectId }))
    }

    /** 시작할 수 있는 비상 접근 정책 (켜져 있고, 대상 그룹이 있으면 그 구성원일 때만) */
    @GetMapping("/break-glass-policies")
    @SelfService
    fun breakGlassPolicies() = ApiResponse.ok(views.breakGlassPolicies(breakGlassService.activePoliciesFor(ApiPrincipal.requireSubjectId())))

    @GetMapping("/break-glass-sessions")
    @SelfService
    fun breakGlassSessions() = ApiResponse.ok(views.breakGlassSessions(breakGlassService.sessionsOf(ApiPrincipal.requireSubjectId())))

    /** 권한 요청·위임 폼의 선택지 */
    @GetMapping("/access-options")
    @SelfService
    fun accessOptions() = ApiResponse.ok(views.accessOptions(ApiPrincipal.requireSubjectId()))

    /** 위임 대상 찾기. 사번이 정확히 같은 사용 중인 사용자의 ID·이름만 준다 */
    @GetMapping("/people")
    @SelfService
    fun person(@RequestParam empNo: String) = ApiResponse.ok(views.personByEmpNo(empNo))
}
