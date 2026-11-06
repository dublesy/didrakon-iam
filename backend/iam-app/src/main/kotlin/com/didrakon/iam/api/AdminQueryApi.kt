package com.didrakon.iam.api

import com.didrakon.iam.api.identity.GroupResponse
import com.didrakon.iam.api.identity.MembershipResponse
import com.didrakon.iam.api.identity.OrganizationResponse
import com.didrakon.iam.api.identity.UserResponse
import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.OrgTarget
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authz.assignment.GroupRoleService
import com.didrakon.iam.authz.assignment.OrganizationRoleService
import com.didrakon.iam.authz.decision.OrgReach
import com.didrakon.iam.authz.policy.Policy
import com.didrakon.iam.authz.policy.PolicyService
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.Permission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.governance.sod.RoleConflictService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserService
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestParam
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/** 목록 응답의 페이지 정보 */
data class PageResponse<T>(val items: List<T>, val page: Int, val size: Int, val total: Long)

data class SubjectName(val subjectId: Long, val subjectName: String, val subjectType: String)

data class OrganizationRoleResponse(
    val orgRoleId: Long, val orgId: Long, val roleId: Long, val scopeId: Long, val applyToDescendants: Boolean, val isActive: Boolean,
)

data class GroupMemberResponse(val subjectId: Long, val sourceType: String, val validFrom: Instant)

data class GroupRoleResponse(val groupRoleId: Long, val groupId: Long, val roleId: Long, val scopeId: Long)

data class RoleResponse(
    val roleId: Long, val roleCode: String, val roleName: String, val roleType: String,
    val isSensitive: Boolean, val isPrivileged: Boolean, val isActive: Boolean, val priority: Int,
)

data class PermissionResponse(
    val permissionId: Long, val permissionCode: String, val permissionName: String, val resourceId: Long, val action: String, val effect: String,
    val isActive: Boolean,
)

data class ScopeResponse(
    val scopeId: Long, val scopeCode: String, val scopeName: String, val scopeType: String,
    val orgId: Long?, val resourceId: Long?, val includeDescendants: Boolean, val isActive: Boolean,
)

data class RolePermissionResponse(val rolePermissionId: Long, val permission: PermissionResponse, val scope: ScopeResponse)

data class RoleDetailResponse(val role: RoleResponse, val permissions: List<RolePermissionResponse>)

data class ResourceResponse(
    val resourceId: Long, val clientId: Long, val parentResourceId: Long?, val resourceKey: String, val resourceName: String,
    val resourceType: String, val sensitivity: String, val isActive: Boolean, val resourcePath: String?,
)

data class ClientResponse(
    val clientId: Long, val clientCode: String, val clientName: String, val clientType: String, val requireMfa: Boolean, val isActive: Boolean,
    val backchannelLogoutUri: String?,
    val supabaseRoleClaim: Boolean,
    val homeUrl: String?,
    val redirectUris: List<String>,
    val postLogoutRedirectUris: List<String>,
    /** openid·profile 포함 */
    val scopes: List<String>,
    /** 비밀값이 있는 클라이언트 (client_secret_basic). false 면 PKCE 를 쓰는 public client */
    val confidential: Boolean,
)

data class PolicyResponse(
    val policyId: Long, val policyCode: String, val policyName: String, val policyType: String, val effect: String, val isActive: Boolean,
    val priority: Int,
)

data class PolicyTargetResponse(val policyTargetId: Long, val permissionId: Long?, val resourceId: Long?, val roleId: Long?)

data class PolicyRuleResponse(
    val ruleGroup: Int, val attributeSource: String, val attributeName: String, val operator: String, val attributeValue: String?, val ruleOrder: Int,
)

data class PolicyVersionResponse(
    val policyVersionId: Long, val version: Int, val status: String, val changeReason: String?, val createdAt: Instant, val rules: List<PolicyRuleResponse>,
)

data class PolicyExceptionResponse(
    val exceptionId: Long, val subjectId: Long?, val resourceId: Long?, val reason: String, val validFrom: Instant, val validUntil: Instant?,
)

data class PolicyDetailResponse(
    val policy: PolicyResponse,
    val targets: List<PolicyTargetResponse>,
    val versions: List<PolicyVersionResponse>,
    val exceptions: List<PolicyExceptionResponse>,
)

data class ConflictExceptionResponse(val exceptionId: Long, val subjectId: Long, val approvedBy: Long, val reason: String, val validUntil: Instant?)

data class RoleConflictResponse(
    val conflictId: Long, val roleIdA: Long, val roleIdB: Long, val severity: String, val description: String?, val isActive: Boolean,
    val exceptions: List<ConflictExceptionResponse>,
)

/** 관리 콘솔 목록·상세 화면용 조회 API. 모두 읽기 전용이다 */
@RestController
@RequestMapping("/api/v1")
class AdminQueryApi(
    private val authorizer: AdminAuthorizer,
    private val userService: UserService,
    private val subjectNames: SubjectNameService,
    private val organizationService: OrganizationService,
    private val membershipService: MembershipService,
    private val groupService: GroupService,
    private val organizationRoleService: OrganizationRoleService,
    private val groupRoleService: GroupRoleService,
    private val catalogService: AuthzCatalogService,
    private val policyService: PolicyService,
    private val conflictService: RoleConflictService,
    private val clientService: SsoClientService,
) {
    // ---------- identity ----------

    /** 조직 단위 관리자는 주 소속 조직이 자기 범위 안인 사용자만 본다 */
    @GetMapping("/users")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ, orgOf = OrgTarget.ANY)
    fun users(
        @RequestParam(required = false) q: String?,
        @RequestParam(required = false) kind: UserKind?,
        @RequestParam(defaultValue = "0") page: Int,
        @RequestParam(defaultValue = "20") size: Int,
    ): ApiResponse<PageResponse<UserResponse>> {
        val result = userService.search(q, kind, authorizer.reach(ApiResources.USER, PermissionAction.READ).orgIdsOrNull(), page, size)
        return ApiResponse.ok(PageResponse(result.content.map(UserResponse::from), result.number, result.size, result.totalElements))
    }

    /** 목록 화면에서 ID 를 이름으로 바꿀 때 쓴다. 최대 200개. 조직 단위 관리자는 범위 안 조직에 소속이 있는 사람만 */
    @GetMapping("/subjects/names")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ, orgOf = OrgTarget.ANY)
    fun names(@RequestParam ids: List<Long>): ApiResponse<List<SubjectName>> =
        ApiResponse.ok(subjectNames.names(ids.take(200), authorizer.reach(ApiResources.USER, PermissionAction.READ).orgIdsOrNull()))

    @GetMapping("/subjects/{subjectId}/memberships")
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun memberships(@PathVariable subjectId: Long) =
        ApiResponse.ok(membershipService.activeMemberships(subjectId).map(MembershipResponse::from))

    /** 조직 단위 관리자는 범위 안 조직만 본다 (상위 조직은 빠지므로 화면은 부모가 없는 조직을 뿌리로 그린다) */
    @GetMapping("/organizations")
    @RequiresPermission(ApiResources.ORGANIZATION, PermissionAction.READ, orgOf = OrgTarget.ANY)
    fun organizations(): ApiResponse<List<OrganizationResponse>> {
        val reach = authorizer.reach(ApiResources.ORGANIZATION, PermissionAction.READ)
        return ApiResponse.ok(organizationService.all().filter { reach.contains(it.requireId()) }.map(OrganizationResponse::from))
    }

    @GetMapping("/organizations/{orgId}/members")
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.READ, orgOf = OrgTarget.ORG)
    fun members(@PathVariable orgId: Long) = ApiResponse.ok(membershipService.activeMembers(orgId).map(MembershipResponse::from))

    @GetMapping("/organizations/{orgId}/roles")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.READ)
    fun organizationRoles(@PathVariable orgId: Long) = ApiResponse.ok(
        organizationRoleService.rules(orgId).map {
            OrganizationRoleResponse(it.requireId(), it.orgId, it.roleId, it.scopeId, it.applyToDescendants, it.isActive)
        },
    )

    @GetMapping("/groups")
    @RequiresPermission(ApiResources.GROUP, PermissionAction.READ)
    fun groups() = ApiResponse.ok(groupService.all().map(GroupResponse::from))

    @GetMapping("/groups/{groupId}/members")
    @RequiresPermission(ApiResources.GROUP, PermissionAction.READ)
    fun groupMembers(@PathVariable groupId: Long) = ApiResponse.ok(
        groupService.members(groupId).map { GroupMemberResponse(it.id.subjectId, it.sourceType.name, it.validFrom) },
    )

    @GetMapping("/groups/{groupId}/roles")
    @RequiresPermission(ApiResources.ASSIGNMENT, PermissionAction.READ)
    fun groupRoles(@PathVariable groupId: Long) =
        ApiResponse.ok(groupRoleService.rules(groupId).map { GroupRoleResponse(it.requireId(), it.groupId, it.roleId, it.scopeId) })

    // ---------- authz ----------

    @GetMapping("/roles")
    @RequiresPermission(ApiResources.ROLE, PermissionAction.READ)
    fun roles() = ApiResponse.ok(catalogService.roles().map(::role))

    @GetMapping("/roles/{roleId}")
    @RequiresPermission(ApiResources.ROLE, PermissionAction.READ)
    fun role(@PathVariable roleId: Long) = ApiResponse.ok(
        RoleDetailResponse(
            role(catalogService.role(roleId)),
            catalogService.rolePermissions(roleId).map { RolePermissionResponse(it.rolePermissionId, permission(it.permission), scope(it.scope)) },
        ),
    )

    @GetMapping("/permissions")
    @RequiresPermission(ApiResources.ROLE, PermissionAction.READ)
    fun permissions(@RequestParam(required = false) resourceId: Long?) = ApiResponse.ok(catalogService.permissions(resourceId).map(::permission))

    @GetMapping("/resources")
    @RequiresPermission(ApiResources.RESOURCE, PermissionAction.READ)
    fun resources(@RequestParam(required = false) clientId: Long?) = ApiResponse.ok(
        catalogService.resources(clientId).map {
            ResourceResponse(
                it.requireId(), it.clientId, it.parentResourceId, it.resourceKey, it.resourceName, it.resourceType.name, it.sensitivity.name, it.isActive, it.resourcePath,
            )
        },
    )

    @GetMapping("/scopes")
    @RequiresPermission(ApiResources.SCOPE, PermissionAction.READ)
    fun scopes() = ApiResponse.ok(catalogService.scopes().map(::scope))

    @GetMapping("/clients")
    @RequiresPermission(ApiResources.CLIENT, PermissionAction.READ)
    fun clients() = ApiResponse.ok(
        clientService.clientsWithSettings().map { (c, s) ->
            ClientResponse(
                c.requireId(), c.clientCode, c.clientName, c.clientType.name, c.requireMfa, c.isActive, c.backchannelLogoutUri, c.supabaseRoleClaim, c.homeUrl,
                s.redirectUris, s.postLogoutRedirectUris, s.scopes, s.confidential,
            )
        },
    )

    @GetMapping("/policies")
    @RequiresPermission(ApiResources.POLICY, PermissionAction.READ)
    fun policies() = ApiResponse.ok(policyService.policies().map(::policy))

    @GetMapping("/policies/{policyId}")
    @RequiresPermission(ApiResources.POLICY, PermissionAction.READ)
    fun policyDetail(@PathVariable policyId: Long): ApiResponse<PolicyDetailResponse> {
        val detail = policyService.detail(policyId)
        return ApiResponse.ok(
            PolicyDetailResponse(
                policy(detail.policy),
                detail.targets.map { PolicyTargetResponse(it.requireId(), it.permissionId, it.resourceId, it.roleId) },
                detail.versions.map { v ->
                    PolicyVersionResponse(
                        v.version.requireId(), v.version.version, v.version.status.name, v.version.changeReason, v.version.createdAt,
                        v.rules.map { PolicyRuleResponse(it.ruleGroup, it.attributeSource.name, it.attributeName, it.operator.name, it.attributeValue, it.ruleOrder) },
                    )
                },
                detail.exceptions.map { PolicyExceptionResponse(it.requireId(), it.subjectId, it.resourceId, it.reason, it.validFrom, it.validUntil) },
            ),
        )
    }

    // ---------- governance ----------

    @GetMapping("/role-conflicts")
    @RequiresPermission(ApiResources.SOD, PermissionAction.READ)
    fun conflicts() = ApiResponse.ok(
        conflictService.all().map { c ->
            RoleConflictResponse(
                c.requireId(), c.roleIdA, c.roleIdB, c.severity.name, c.description, c.isActive,
                conflictService.exceptions(c.requireId()).map { ConflictExceptionResponse(it.requireId(), it.subjectId, it.approvedBy, it.reason, it.validUntil) },
            )
        },
    )

    private fun role(r: Role) =
        RoleResponse(r.requireId(), r.roleCode, r.roleName, r.roleType.name, r.isSensitive, r.isPrivileged, r.isActive, r.priority)

    private fun permission(p: Permission) =
        PermissionResponse(p.requireId(), p.permissionCode, p.permissionName, p.resourceId, p.action.name, p.effect.name, p.isActive)

    private fun scope(s: Scope) =
        ScopeResponse(s.requireId(), s.scopeCode, s.scopeName, s.scopeType.name, s.orgId, s.resourceId, s.includeDescendants, s.isActive)

    private fun policy(p: Policy) =
        PolicyResponse(p.requireId(), p.policyCode, p.policyName, p.policyType.name, p.effect.name, p.isActive, p.priority)
}

/** subject ID → 표시 이름 */
@Service
@Transactional(readOnly = true)
class SubjectNameService(
    private val subjectRepository: SubjectRepository,
    private val membershipRepository: SubjectOrganizationRepository,
) {
    /** [orgIds] 가 null 이면 전부, 아니면 그 조직들에 활성 소속이 있는 subject 만 */
    fun names(ids: List<Long>, orgIds: Set<Long>?): List<SubjectName> {
        val visible = if (orgIds == null) {
            ids
        } else {
            membershipRepository.findActiveBySubjectIdIn(ids.ifEmpty { listOf(-1L) }).filter { it.orgId in orgIds }.map { it.subjectId }.distinct()
        }
        return subjectRepository.findAllById(visible).map { SubjectName(it.requireId(), it.subjectName, it.subjectType.name) }
    }
}

/** 조직 제한이 없으면 null, 있으면 그 조직 집합 */
fun OrgReach.orgIdsOrNull(): Set<Long>? = when (this) {
    OrgReach.All -> null
    is OrgReach.Orgs -> orgIds
}
