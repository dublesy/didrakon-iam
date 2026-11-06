package com.didrakon.iam.api.authz

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authz.assignment.GroupRoleService
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.assignment.RoleAssignment
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.AuthorizationResult
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.policy.AttributeSource
import com.didrakon.iam.authz.policy.PolicyEffect
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.policy.PolicyTargetSpec
import com.didrakon.iam.authz.policy.PolicyType
import com.didrakon.iam.authz.policy.PolicyVersionService
import com.didrakon.iam.authz.policy.RuleOperator
import com.didrakon.iam.authz.policy.RuleSpec
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.common.context.RequestContextHolder
import com.didrakon.iam.common.error.NotFoundException
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/** 생성 결과처럼 ID 만 돌려줄 때 */
data class IdResponse(val id: Long)

// ---------- 카탈로그 (리소스·역할·권한·scope) ----------

data class CreateResourceRequest(
    val clientId: Long,
    @field:NotBlank @field:Size(max = 200) val resourceKey: String,
    @field:NotBlank @field:Size(max = 200) val resourceName: String,
    val resourceType: ResourceType,
    val sensitivity: Sensitivity,
    val parentResourceId: Long? = null,
    @field:Size(max = 1000) val resourcePath: String? = null,
)

data class CreateRoleRequest(
    @field:NotBlank @field:Size(max = 100) val roleCode: String,
    @field:NotBlank @field:Size(max = 200) val roleName: String,
    val roleType: RoleType,
    val isSensitive: Boolean = false,
    val isPrivileged: Boolean = false,
    val priority: Int = 0,
)

data class CreatePermissionRequest(
    @field:NotBlank @field:Size(max = 100) val permissionCode: String,
    @field:NotBlank @field:Size(max = 200) val permissionName: String,
    val resourceId: Long,
    val action: PermissionAction,
    val effect: PermissionEffect = PermissionEffect.ALLOW,
)

data class GrantPermissionRequest(val permissionId: Long, val scopeId: Long? = null)

data class CreateScopeRequest(
    @field:NotBlank @field:Size(max = 100) val scopeCode: String,
    @field:NotBlank @field:Size(max = 200) val scopeName: String,
    val scopeType: ScopeType,
    val orgId: Long? = null,
    val resourceId: Long? = null,
    val includeDescendants: Boolean = false,
)

@RestController
@RequestMapping("/api/v1")
class CatalogApi(private val catalogService: AuthzCatalogService, private val authorizer: AdminAuthorizer) {
    @PostMapping("/resources")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.RESOURCE, PermissionAction.CREATE)
    fun createResource(@Valid @RequestBody r: CreateResourceRequest) = ApiResponse.ok(
        IdResponse(catalogService.createResource(r.clientId, r.resourceKey, r.resourceName, r.resourceType, r.sensitivity, r.parentResourceId, r.resourcePath).requireId()),
    )

    @PostMapping("/roles")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ROLE, PermissionAction.CREATE)
    fun createRole(@Valid @RequestBody r: CreateRoleRequest) = ApiResponse.ok(
        IdResponse(catalogService.createRole(r.roleCode, r.roleName, r.roleType, r.isSensitive, r.isPrivileged, r.priority).requireId()),
    )

    @PostMapping("/roles/{roleId}/deactivate")
    @RequiresPermission(ApiResources.ROLE, PermissionAction.UPDATE)
    fun deactivateRole(@PathVariable roleId: Long): ApiResponse<Unit> {
        catalogService.deactivateRole(roleId)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ROLE, PermissionAction.CREATE)
    fun createPermission(@Valid @RequestBody r: CreatePermissionRequest) = ApiResponse.ok(
        IdResponse(catalogService.createPermission(r.permissionCode, r.permissionName, r.resourceId, r.action, r.effect).requireId()),
    )

    @PostMapping("/roles/{roleId}/permissions")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ROLE, PermissionAction.UPDATE)
    fun grantPermission(@PathVariable roleId: Long, @RequestBody r: GrantPermissionRequest): ApiResponse<IdResponse> {
        authorizer.requirePermissionAllowedForRole(roleId, r.permissionId)
        return ApiResponse.ok(IdResponse(catalogService.grantPermission(roleId, r.permissionId, r.scopeId).requireId()))
    }

    @PostMapping("/scopes")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.SCOPE, PermissionAction.CREATE)
    fun createScope(@Valid @RequestBody r: CreateScopeRequest) = ApiResponse.ok(
        IdResponse(catalogService.createScope(r.scopeCode, r.scopeName, r.scopeType, r.orgId, r.resourceId, r.includeDescendants).requireId()),
    )
}

// ---------- 역할 할당과 조직·그룹 규칙 ----------

data class AssignRoleRequest(
    val subjectId: Long,
    val roleId: Long,
    val scopeId: Long? = null,
    val validUntil: Instant? = null,
    @field:Size(max = 1000) val reason: String? = null,
)

/** 직접 할당의 새 종료 시각. null 이면 기한 없음 */
data class ChangeAssignmentRequest(val validUntil: Instant? = null, @field:Size(max = 500) val reason: String? = null)

data class OrganizationRoleRequest(val orgId: Long, val roleId: Long, val scopeId: Long? = null, val applyToDescendants: Boolean = false)

data class GroupRoleRequest(val groupId: Long, val roleId: Long, val scopeId: Long? = null)

data class AssignmentResponse(
    val assignmentId: Long,
    val roleId: Long,
    val scopeId: Long,
    val sourceType: String,
    val sourceId: Long?,
    val validFrom: Instant,
    val validUntil: Instant?,
    val reviewRequired: Boolean,
) {
    companion object {
        fun from(a: RoleAssignment) =
            AssignmentResponse(a.requireId(), a.roleId, a.scopeId, a.sourceType.name, a.sourceId, a.validFrom, a.validUntil, a.reviewRequired)
    }
}

@RestController
@RequestMapping("/api/v1")
class AssignmentApi(
    private val assignmentService: RoleAssignmentService,
    private val organizationRoleService: OrganizationRoleService,
    private val groupRoleService: GroupRoleService,
    private val authorizer: AdminAuthorizer,
) {
    @PostMapping("/assignments")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.CREATE)
    fun assign(@Valid @RequestBody r: AssignRoleRequest) = ApiResponse.ok(
        AssignmentResponse.from(assignmentService.assignDirect(r.subjectId, r.roleId, r.scopeId, r.validUntil, ApiPrincipal.subjectId(), r.reason)),
    )

    @DeleteMapping("/assignments/{assignmentId}")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.DELETE)
    fun revoke(@PathVariable assignmentId: Long, @RequestParam(required = false) reason: String?): ApiResponse<Unit> {
        assignmentService.revoke(assignmentId, ApiPrincipal.subjectId(), reason)
        return ApiResponse.ok(Unit)
    }

    /** 직접 할당의 종료 시각 변경 (연장·단축·기한 없앰). 이력은 MODIFY 로 남는다 */
    @PutMapping("/assignments/{assignmentId}")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.UPDATE)
    fun changeValidUntil(@PathVariable assignmentId: Long, @Valid @RequestBody r: ChangeAssignmentRequest) = ApiResponse.ok(
        AssignmentResponse.from(assignmentService.changeValidUntil(assignmentId, r.validUntil, ApiPrincipal.subjectId(), r.reason)),
    )

    @GetMapping("/subjects/{subjectId}/assignments")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.READ)
    fun effective(@PathVariable subjectId: Long) =
        ApiResponse.ok(assignmentService.effectiveAssignments(subjectId).map(AssignmentResponse::from))

    @PostMapping("/organization-roles")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.CREATE)
    fun createOrganizationRole(@RequestBody r: OrganizationRoleRequest): ApiResponse<IdResponse> {
        authorizer.requireNotConsoleRole(r.roleId)
        return ApiResponse.ok(IdResponse(organizationRoleService.create(r.orgId, r.roleId, r.scopeId, r.applyToDescendants).requireId()))
    }

    @DeleteMapping("/organization-roles/{orgRoleId}")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.DELETE)
    fun deactivateOrganizationRole(@PathVariable orgRoleId: Long): ApiResponse<Unit> {
        organizationRoleService.deactivate(orgRoleId)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/group-roles")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.CREATE)
    fun createGroupRole(@RequestBody r: GroupRoleRequest): ApiResponse<IdResponse> {
        authorizer.requireNotConsoleRole(r.roleId)
        return ApiResponse.ok(IdResponse(groupRoleService.create(r.groupId, r.roleId, r.scopeId).requireId()))
    }

    @DeleteMapping("/group-roles/{groupRoleId}")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.DELETE)
    fun deleteGroupRole(@PathVariable groupRoleId: Long): ApiResponse<Unit> {
        groupRoleService.delete(groupRoleId)
        return ApiResponse.ok(Unit)
    }
}

// ---------- 정책 ----------

data class CreatePolicyRequest(
    @field:NotBlank @field:Size(max = 100) val policyCode: String,
    @field:NotBlank @field:Size(max = 200) val policyName: String,
    val policyType: PolicyType,
    val effect: PolicyEffect,
    val targets: List<PolicyTargetSpec>,
    val priority: Int = 0,
)

data class RuleRequest(
    val ruleGroup: Int,
    val attributeSource: AttributeSource,
    @field:NotBlank val attributeName: String,
    val operator: RuleOperator,
    /** JSON 문자열. EXISTS 는 생략 */
    val attributeValue: String? = null,
    val ruleOrder: Int = 0,
)

data class CreateVersionRequest(@field:Valid val rules: List<RuleRequest>, @field:Size(max = 1000) val changeReason: String? = null)

/** 대상 묶음 전체. 보낸 것으로 바꾼다 */
data class ReplacePolicyTargetsRequest(val targets: List<PolicyTargetSpec>)

data class PolicyExceptionRequest(val subjectId: Long? = null, val resourceId: Long? = null, @field:NotBlank val reason: String, val validUntil: Instant? = null)

@RestController
@RequestMapping("/api/v1")
class PolicyApi(
    private val policyService: PolicyService,
    private val versionService: PolicyVersionService,
    private val authorizer: AdminAuthorizer,
) {
    @PostMapping("/policies")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.POLICY, PermissionAction.CREATE)
    fun create(@Valid @RequestBody r: CreatePolicyRequest) =
        ApiResponse.ok(IdResponse(policyService.create(r.policyCode, r.policyName, r.policyType, r.effect, r.targets, r.priority).requireId()))

    /** 대상(권한·리소스·역할)을 바꾼다. 다음 판정부터 적용된다 */
    @PutMapping("/policies/{policyId}/targets")
    @RequiresPermission(ApiResources.POLICY, PermissionAction.UPDATE)
    fun replaceTargets(@PathVariable policyId: Long, @Valid @RequestBody r: ReplacePolicyTargetsRequest): ApiResponse<Unit> {
        authorizer.requireEditablePolicy(policyId)
        policyService.replaceTargets(policyId, r.targets)
        return ApiResponse.ok(Unit)
    }

    /** 규칙은 새 버전(DRAFT)으로만 바꾼다 */
    @PostMapping("/policies/{policyId}/versions")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.POLICY, PermissionAction.UPDATE)
    fun createVersion(@PathVariable policyId: Long, @Valid @RequestBody r: CreateVersionRequest): ApiResponse<IdResponse> {
        authorizer.requireEditablePolicy(policyId)
        return ApiResponse.ok(
            IdResponse(
                versionService.createVersion(
                    policyId,
                    r.rules.map { RuleSpec(it.ruleGroup, it.attributeSource, it.attributeName, it.operator, it.attributeValue, it.ruleOrder) },
                    r.changeReason,
                    ApiPrincipal.subjectId(),
                ).requireId(),
            ),
        )
    }

    @PostMapping("/policy-versions/{versionId}/activate")
    @RequiresPermission(ApiResources.POLICY, PermissionAction.UPDATE)
    fun activate(@PathVariable versionId: Long): ApiResponse<Unit> {
        versionService.activate(versionId)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/policies/{policyId}/exceptions")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.POLICY, PermissionAction.UPDATE)
    fun addException(@PathVariable policyId: Long, @Valid @RequestBody r: PolicyExceptionRequest): ApiResponse<IdResponse> {
        // 관리 API MFA 정책에 예외를 두면 그 대상은 비밀번호만으로 관리 API 를 쓴다. 끄기·대상 변경과 같이 막는다
        authorizer.requireEditablePolicy(policyId)
        return ApiResponse.ok(IdResponse(policyService.addException(policyId, r.subjectId, r.resourceId, r.reason, r.validUntil).requireId()))
    }
}

// ---------- 권한 판정 (다른 시스템이 호출) ----------

/** 리소스는 resourceId 또는 (clientCode, resourceKey) 로 지정한다 */
data class CheckRequest(
    val subjectId: Long,
    val resourceId: Long? = null,
    val clientCode: String? = null,
    val resourceKey: String? = null,
    val action: PermissionAction,
    val orgId: Long? = null,
    val context: Map<String, Any?> = emptyMap(),
    val session: Map<String, Any?> = emptyMap(),
)

@RestController
@RequestMapping("/api/v1/authz")
class CheckApi(
    private val pdp: PolicyDecisionPoint,
    private val ssoClientRepository: SsoClientRepository,
    private val resourceRepository: ResourceRepository,
) {
    /** 판정 결과(근거 포함)를 돌려준다. 거부도 200 응답의 decision 으로 알린다 */
    @PostMapping("/check")
    @RequiresPermission(ApiResources.AUTHZ_CHECK, PermissionAction.EXECUTE, scope = ApiResources.AUTHZ_CHECK_SCOPE)
    fun check(@RequestBody r: CheckRequest): ApiResponse<AuthorizationResult> = ApiResponse.ok(
        pdp.decide(
            AuthorizationRequest(
                subjectId = r.subjectId,
                resourceId = resolveResource(r),
                action = r.action,
                orgId = r.orgId,
                context = r.context,
                session = r.session,
                traceId = RequestContextHolder.current()?.traceId,
            ),
        ),
    )

    private fun resolveResource(r: CheckRequest): Long {
        r.resourceId?.let { return it }
        val clientCode = r.clientCode ?: throw NotFoundException("리소스", "resourceId 또는 clientCode·resourceKey 필요")
        val clientId = ssoClientRepository.findByClientCode(clientCode)?.requireId() ?: throw NotFoundException("클라이언트", clientCode)
        val key = r.resourceKey ?: throw NotFoundException("리소스", "resourceKey 필요")
        return resourceRepository.findByClientIdAndResourceKey(clientId, key)?.requireId() ?: throw NotFoundException("리소스", key)
    }
}
