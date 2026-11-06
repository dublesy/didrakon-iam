package com.didrakon.iam.api.admin

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.OrgTarget
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.client.ClientLoginChange
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.common.error.BusinessRuleException
import org.springframework.data.repository.findByIdOrNull
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.PermissionAction.UPDATE
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import jakarta.validation.Valid
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.time.LocalDate

data class UpdateUserRequest(
    @field:NotBlank @field:Size(max = 200) val name: String,
    @field:Email @field:Size(max = 200) val email: String? = null,
    @field:Size(max = 30) val phone: String? = null,
    val hireDate: LocalDate? = null,
)

data class RetireRequest(val retireDate: LocalDate? = null)

data class UpdateOrganizationRequest(@field:NotBlank @field:Size(max = 200) val orgName: String, val orgType: OrgType)

data class UpdateGroupRequest(@field:NotBlank @field:Size(max = 200) val groupName: String, @field:Size(max = 2000) val ruleExpression: String? = null)

data class UpdateRoleRequest(
    @field:NotBlank @field:Size(max = 200) val roleName: String,
    val roleType: RoleType,
    val priority: Int = 0,
    val isSensitive: Boolean = false,
    val isPrivileged: Boolean = false,
)

data class UpdateResourceRequest(
    @field:NotBlank @field:Size(max = 200) val resourceName: String,
    val resourceType: ResourceType,
    @field:Size(max = 500) val resourcePath: String? = null,
    val sensitivity: Sensitivity,
)

data class RenameRequest(@field:NotBlank @field:Size(max = 200) val name: String)

data class UpdateScopeRequest(@field:NotBlank @field:Size(max = 200) val scopeName: String, val includeDescendants: Boolean = false)

data class UpdatePolicyRequest(@field:NotBlank @field:Size(max = 200) val policyName: String, val priority: Int = 0)

/** 역할 쌍은 바꾸지 않는다 */
data class UpdateConflictRequest(val severity: RiskLevel, @field:Size(max = 1000) val description: String? = null)

data class UpdateClientRequest(
    @field:NotBlank @field:Size(max = 200) val clientName: String,
    val requireMfa: Boolean = false,
    @field:Size(max = 500) val backchannelLogoutUri: String? = null,
    val supabaseRoleClaim: Boolean = false,
    @field:Size(max = 500) val homeUrl: String? = null,
    /** 아래 셋은 null 이면 그대로 둔다. 관리 콘솔 클라이언트(iam-admin)는 바꿀 수 없다 */
    val redirectUris: Set<String>? = null,
    val postLogoutRedirectUris: Set<String>? = null,
    /** openid·profile 은 사용자 로그인 클라이언트에 늘 들어가므로 빼도 된다 */
    val scopes: Set<String>? = null,
)

/** clientSecret 은 이 응답에서 한 번만 보여준다 */
data class RotatedClientSecretResponse(val clientSecret: String)

/**
 * 관리 화면의 수정·사용 안 함·다시 사용·연결 회수. 기준 데이터는 지우지 않고 끈다 (감사 기록과 과거 판정 근거가 가리키므로).
 * 모든 변경은 서비스가 AdminChangeEvent 로 감사 기록에 남긴다.
 */
@RestController
@RequestMapping("/api/v1")
class AdminEditApi(
    private val userService: UserService,
    private val organizationService: OrganizationService,
    private val groupService: GroupService,
    private val catalogService: AuthzCatalogService,
    private val policyService: PolicyService,
    private val conflictService: RoleConflictService,
    private val clientService: SsoClientService,
    private val ssoClientRepository: SsoClientRepository,
    private val resourceRepository: ResourceRepository,
    private val permissionRepository: PermissionRepository,
    private val authorizer: AdminAuthorizer,
) {
    // ---------- 사용자 ----------
    @PutMapping("/users/{subjectId}")
    @RequiresPermission(ApiResources.USER, UPDATE, orgOf = OrgTarget.SUBJECT)
    fun updateUser(@PathVariable subjectId: Long, @Valid @RequestBody r: UpdateUserRequest) =
        done { userService.update(subjectId, r.name, r.email, r.phone, r.hireDate) }

    @PostMapping("/users/{subjectId}/activate")
    @RequiresPermission(ApiResources.USER, UPDATE, orgOf = OrgTarget.SUBJECT)
    fun activateUser(@PathVariable subjectId: Long) = done { userService.changeStatus(subjectId, SubjectStatus.ACTIVE) }

    @PostMapping("/users/{subjectId}/deactivate")
    @RequiresPermission(ApiResources.USER, UPDATE, orgOf = OrgTarget.SUBJECT)
    fun deactivateUser(@PathVariable subjectId: Long) = done { userService.changeStatus(subjectId, SubjectStatus.DISABLED) }

    /** 퇴사 예약 취소 */
    @DeleteMapping("/users/{subjectId}/retire")
    @RequiresPermission(ApiResources.USER, UPDATE, orgOf = OrgTarget.SUBJECT)
    fun cancelRetire(@PathVariable subjectId: Long) = done { userService.cancelScheduledRetire(subjectId) }

    /** 퇴사. 퇴사일이 오늘 이후면 예약, 아니면 지금 처리(되돌릴 수 없음) */
    @PostMapping("/users/{subjectId}/retire")
    @RequiresPermission(ApiResources.USER, UPDATE, orgOf = OrgTarget.SUBJECT)
    fun retireUser(@PathVariable subjectId: Long, @Valid @RequestBody r: RetireRequest) = done { userService.retire(subjectId, r.retireDate) }

    // ---------- 조직·그룹 ----------
    @PutMapping("/organizations/{orgId}")
    @RequiresPermission(ApiResources.ORGANIZATION, UPDATE, orgOf = OrgTarget.ORG)
    fun updateOrganization(@PathVariable orgId: Long, @Valid @RequestBody r: UpdateOrganizationRequest) =
        done { organizationService.update(orgId, r.orgName, r.orgType) }

    @PostMapping("/organizations/{orgId}/activate")
    @RequiresPermission(ApiResources.ORGANIZATION, UPDATE, orgOf = OrgTarget.ORG)
    fun activateOrganization(@PathVariable orgId: Long) = done { organizationService.changeActive(orgId, true) }

    @PostMapping("/organizations/{orgId}/deactivate")
    @RequiresPermission(ApiResources.ORGANIZATION, UPDATE, orgOf = OrgTarget.ORG)
    fun deactivateOrganization(@PathVariable orgId: Long) = done { organizationService.changeActive(orgId, false) }

    @PutMapping("/groups/{groupId}")
    @RequiresPermission(ApiResources.GROUP, UPDATE)
    fun updateGroup(@PathVariable groupId: Long, @Valid @RequestBody r: UpdateGroupRequest) =
        done { groupService.update(groupId, r.groupName, r.ruleExpression) }

    @PostMapping("/groups/{groupId}/activate")
    @RequiresPermission(ApiResources.GROUP, UPDATE)
    fun activateGroup(@PathVariable groupId: Long) = done { groupService.changeActive(groupId, true) }

    @PostMapping("/groups/{groupId}/deactivate")
    @RequiresPermission(ApiResources.GROUP, UPDATE)
    fun deactivateGroup(@PathVariable groupId: Long) = done { groupService.changeActive(groupId, false) }

    // ---------- 역할·리소스·권한·범위 ----------
    @PutMapping("/roles/{roleId}")
    @RequiresPermission(ApiResources.ROLE, UPDATE)
    fun updateRole(@PathVariable roleId: Long, @Valid @RequestBody r: UpdateRoleRequest) =
        done { catalogService.updateRole(roleId, r.roleName, r.roleType, r.priority, r.isSensitive, r.isPrivileged) }

    @PostMapping("/roles/{roleId}/activate")
    @RequiresPermission(ApiResources.ROLE, UPDATE)
    fun activateRole(@PathVariable roleId: Long) = done { catalogService.changeRoleActive(roleId, true) }

    @DeleteMapping("/role-permissions/{rolePermissionId}")
    @RequiresPermission(ApiResources.ROLE, UPDATE)
    fun removeRolePermission(@PathVariable rolePermissionId: Long) = done { catalogService.removeRolePermission(rolePermissionId) }

    @PutMapping("/resources/{resourceId}")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun updateResource(@PathVariable resourceId: Long, @Valid @RequestBody r: UpdateResourceRequest) =
        done { catalogService.updateResource(resourceId, r.resourceName, r.resourceType, r.resourcePath, r.sensitivity) }

    @PostMapping("/resources/{resourceId}/activate")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun activateResource(@PathVariable resourceId: Long) = done { catalogService.changeResourceActive(resourceId, true) }

    @PostMapping("/resources/{resourceId}/deactivate")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun deactivateResource(@PathVariable resourceId: Long) = done {
        guardConsoleResource(resourceId)
        catalogService.changeResourceActive(resourceId, false)
    }

    @PutMapping("/permissions/{permissionId}")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun renamePermission(@PathVariable permissionId: Long, @Valid @RequestBody r: RenameRequest) =
        done { catalogService.renamePermission(permissionId, r.name) }

    @PostMapping("/permissions/{permissionId}/activate")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun activatePermission(@PathVariable permissionId: Long) = done { catalogService.changePermissionActive(permissionId, true) }

    @PostMapping("/permissions/{permissionId}/deactivate")
    @RequiresPermission(ApiResources.RESOURCE, UPDATE)
    fun deactivatePermission(@PathVariable permissionId: Long) = done {
        permissionRepository.findByIdOrNull(permissionId)?.let { guardConsoleResource(it.resourceId) }
        catalogService.changePermissionActive(permissionId, false)
    }

    @PutMapping("/scopes/{scopeId}")
    @RequiresPermission(ApiResources.SCOPE, UPDATE)
    fun updateScope(@PathVariable scopeId: Long, @Valid @RequestBody r: UpdateScopeRequest) =
        done { catalogService.updateScope(scopeId, r.scopeName, r.includeDescendants) }

    @PostMapping("/scopes/{scopeId}/activate")
    @RequiresPermission(ApiResources.SCOPE, UPDATE)
    fun activateScope(@PathVariable scopeId: Long) = done { catalogService.changeScopeActive(scopeId, true) }

    @PostMapping("/scopes/{scopeId}/deactivate")
    @RequiresPermission(ApiResources.SCOPE, UPDATE)
    fun deactivateScope(@PathVariable scopeId: Long) = done { catalogService.changeScopeActive(scopeId, false) }

    // ---------- 정책·직무 분리 ----------
    @PutMapping("/policies/{policyId}")
    @RequiresPermission(ApiResources.POLICY, UPDATE)
    fun updatePolicy(@PathVariable policyId: Long, @Valid @RequestBody r: UpdatePolicyRequest) =
        done { policyService.update(policyId, r.policyName, r.priority) }

    @PostMapping("/policies/{policyId}/activate")
    @RequiresPermission(ApiResources.POLICY, UPDATE)
    fun activatePolicy(@PathVariable policyId: Long) = done { policyService.changeActive(policyId, true) }

    @PostMapping("/policies/{policyId}/deactivate")
    @RequiresPermission(ApiResources.POLICY, UPDATE)
    fun deactivatePolicy(@PathVariable policyId: Long) = done {
        authorizer.requireEditablePolicy(policyId)
        policyService.changeActive(policyId, false)
    }

    @DeleteMapping("/policy-exceptions/{exceptionId}")
    @RequiresPermission(ApiResources.POLICY, UPDATE)
    fun endPolicyException(@PathVariable exceptionId: Long) = done { policyService.endException(exceptionId) }

    @PutMapping("/role-conflicts/{conflictId}")
    @RequiresPermission(ApiResources.SOD, UPDATE)
    fun updateConflict(@PathVariable conflictId: Long, @Valid @RequestBody r: UpdateConflictRequest) =
        done { conflictService.update(conflictId, r.severity, r.description) }

    @PostMapping("/role-conflicts/{conflictId}/activate")
    @RequiresPermission(ApiResources.SOD, UPDATE)
    fun activateConflict(@PathVariable conflictId: Long) = done { conflictService.changeActive(conflictId, true) }

    @PostMapping("/role-conflicts/{conflictId}/deactivate")
    @RequiresPermission(ApiResources.SOD, UPDATE)
    fun deactivateConflict(@PathVariable conflictId: Long) = done { conflictService.changeActive(conflictId, false) }

    @DeleteMapping("/role-conflict-exceptions/{exceptionId}")
    @RequiresPermission(ApiResources.SOD, UPDATE)
    fun endConflictException(@PathVariable exceptionId: Long) = done { conflictService.endException(exceptionId) }

    // ---------- SSO 클라이언트 ----------
    @PutMapping("/clients/{ssoClientId}")
    @RequiresPermission(ApiResources.CLIENT, UPDATE)
    fun updateClient(@PathVariable ssoClientId: Long, @Valid @RequestBody r: UpdateClientRequest) =
        done {
            clientService.update(
                ssoClientId, r.clientName, r.requireMfa, r.backchannelLogoutUri, r.supabaseRoleClaim, r.homeUrl,
                ClientLoginChange(r.redirectUris, r.postLogoutRedirectUris, r.scopes), ApiResources.CLIENT_CODE,
            )
        }

    /** 비밀값 재발급. 이전 비밀값은 바로 쓸 수 없게 된다. public client 는 409 */
    @PostMapping("/clients/{ssoClientId}/rotate-secret")
    @RequiresPermission(ApiResources.CLIENT, UPDATE)
    fun rotateClientSecret(@PathVariable ssoClientId: Long) = ApiResponse.ok(RotatedClientSecretResponse(clientService.rotateSecret(ssoClientId)))

    @PostMapping("/clients/{ssoClientId}/activate")
    @RequiresPermission(ApiResources.CLIENT, UPDATE)
    fun activateClient(@PathVariable ssoClientId: Long) = done { clientService.changeActive(ssoClientId, true, ApiResources.CLIENT_CODE) }

    @PostMapping("/clients/{ssoClientId}/deactivate")
    @RequiresPermission(ApiResources.CLIENT, UPDATE)
    fun deactivateClient(@PathVariable ssoClientId: Long) = done { clientService.changeActive(ssoClientId, false, ApiResources.CLIENT_CODE) }

    /** 관리 콘솔 자신의 리소스·권한을 끄면 관리자도 관리 API 에서 거부되어 화면으로 되돌릴 수 없다 */
    private fun guardConsoleResource(resourceId: Long) {
        val consoleClientId = ssoClientRepository.findByClientCode(ApiResources.CLIENT_CODE)?.requireId() ?: return
        if (resourceRepository.findByIdOrNull(resourceId)?.clientId == consoleClientId) {
            throw BusinessRuleException("IAM 관리 콘솔의 리소스·권한은 끌 수 없습니다")
        }
    }

    private fun done(change: () -> Any?): ApiResponse<Unit> {
        change()
        return ApiResponse.ok(Unit)
    }
}
