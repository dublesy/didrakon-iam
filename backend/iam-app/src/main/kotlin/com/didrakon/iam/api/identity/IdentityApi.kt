package com.didrakon.iam.api.identity

import com.didrakon.iam.api.support.AdminAuthorizer
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.OrgTarget
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.credential.LocalCredential
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.common.error.BusinessRuleException
import com.didrakon.iam.common.error.NotFoundException
import com.didrakon.iam.identity.group.GroupMemberService
import com.didrakon.iam.identity.group.GroupService
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.Organization
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.organization.SubjectOrganization
import com.didrakon.iam.identity.subject.EmploymentStatus
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserService
import jakarta.validation.Valid
import jakarta.validation.constraints.Email
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Pattern
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.stereotype.Service
import org.springframework.transaction.annotation.Transactional
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.PutMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Clock
import java.time.Instant
import java.time.LocalDate

// ---------- 사용자 ----------

data class CreateUserRequest(
    /** 임직원은 필수, 외부 사용자는 비운다 */
    @field:Size(max = 50) @field:Pattern(regexp = ".*\\S.*", message = "사번이 비어 있습니다") val empNo: String? = null,
    @field:NotBlank @field:Size(max = 200) val name: String,
    /** 외부 사용자는 필수 (외부 사용자끼리 고유) */
    @field:Email @field:Size(max = 255) val email: String? = null,
    @field:Size(max = 30) val phone: String? = null,
    val hireDate: LocalDate? = null,
    /** 함께 넣으면 LOCAL 로그인 계정도 만든다 */
    @field:Size(max = 100) val loginId: String? = null,
    val password: String? = null,
    val userKind: UserKind = UserKind.EMPLOYEE,
    /** 주 소속(PRIMARY) 조직. 함께 만든다. 조직 단위 관리자와 외부 사용자(고객사 조직)는 필수 */
    val primaryOrgId: Long? = null,
)

data class ChangePasswordRequest(@field:NotBlank val password: String)

data class UserResponse(
    val subjectId: Long,
    val userKind: UserKind,
    /** 외부 사용자는 null */
    val empNo: String?,
    val name: String,
    val email: String?,
    val phone: String?,
    val status: SubjectStatus,
    val employmentStatus: EmploymentStatus,
    val hireDate: LocalDate?,
    /** 퇴사일. 상태가 RETIRED 가 아니면 퇴사 예정일(예약) */
    val retireDate: LocalDate?,
) {
    companion object {
        fun from(user: User) =
            UserResponse(user.requireId(), user.userKind, user.empNo, user.name, user.email, user.phone, user.status, user.employmentStatus, user.hireDate, user.retireDate)
    }
}

/** LOCAL 로그인 계정의 로그인 ID·비밀번호·잠금 상태. 비밀번호 hash 는 주지 않는다 */
data class CredentialStateResponse(
    val loginId: String,
    val locked: Boolean,
    /** 잠금이 풀리는 시각. 잠기지 않았으면 null */
    val lockedUntil: Instant?,
    val mustChangePassword: Boolean,
    val passwordChangedAt: Instant,
    val passwordExpireAt: Instant?,
) {
    companion object {
        fun from(loginId: String, credential: LocalCredential, now: Instant): CredentialStateResponse {
            val locked = credential.isLockedAt(now)
            return CredentialStateResponse(
                loginId, locked, credential.lockedUntil.takeIf { locked }, credential.mustChangePassword, credential.passwordChangedAt, credential.passwordExpireAt,
            )
        }
    }
}

/** 로그인 계정이 없는 사용자에게 만들어 줄 LOCAL 계정. 첫 비밀번호는 다음 로그인에서 본인이 바꿔야 한다 */
data class CreateLoginAccountRequest(
    @field:NotBlank @field:Size(max = 100) val loginId: String,
    @field:NotBlank @field:Size(max = 200) val password: String,
)

/** 사용자(identity)와 로그인 계정(authn)을 한 트랜잭션으로 만든다 */
@Service
@Transactional
class UserRegistrationService(
    private val userService: UserService,
    private val accountService: LocalAccountService,
) {
    fun register(request: CreateUserRequest): User {
        val user = userService.create(
            request.empNo, request.name, request.email, request.phone, request.hireDate, request.userKind, request.primaryOrgId,
        )
        // 관리자가 정한 첫 비밀번호이므로 로그인 계정 만들기와 같이 다음 로그인에서 본인이 바꾸게 한다
        if (request.loginId != null) accountService.createAccountByAdmin(user.requireId(), request.loginId.trim(), request.password.orEmpty())
        return user
    }
}

/** 계정 연결용 조회. 개인정보가 URL·로그에 남지 않도록 본문으로 받는다. 한 번에 합쳐 1000건까지 */
data class UserLookupRequest(
    @field:Size(max = 1000) val empNos: List<String> = emptyList(),
    @field:Size(max = 1000) val emails: List<String> = emptyList(),
)

/** 입력값 하나에 대한 결과. matches 가 둘 이상이면 사람이 골라야 한다 (이메일 중복) */
data class UserLookupMatch(val key: String, val matchedBy: String, val matches: List<UserResponse>)

@RestController
@RequestMapping("/api/v1/users")
class UserApi(
    private val authorizer: AdminAuthorizer,
    private val registrationService: UserRegistrationService,
    private val userService: UserService,
    private val accountService: LocalAccountService,
    private val clock: Clock,
) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.USER, PermissionAction.CREATE, orgOf = OrgTarget.ANY)
    fun create(@Valid @RequestBody request: CreateUserRequest): ApiResponse<UserResponse> {
        // 조직 단위 관리자는 자기 범위 안 조직에만 만들 수 있다. 조직 없이 만드는 것은 전체 범위 권한만
        authorizer.requireOrg(ApiResources.USER, PermissionAction.CREATE, request.primaryOrgId)
        return ApiResponse.ok(UserResponse.from(registrationService.register(request)))
    }

    /**
     * 연동 시스템이 기존 계정을 IAM 사용자(subject ID)와 잇는 일회성 작업용. 사번·이메일 목록을 받아 맞는 사용자를 돌려준다.
     * 전체 범위 조회 권한만 쓸 수 있다 (조직 단위 관리자는 403)
     */
    @PostMapping("/lookup")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ)
    fun lookup(@Valid @RequestBody request: UserLookupRequest): ApiResponse<List<UserLookupMatch>> {
        if (request.empNos.size + request.emails.size > 1000) throw BusinessRuleException("한 번에 1000건까지 조회할 수 있습니다")
        val (byEmpNo, byEmail) = userService.lookup(request.empNos, request.emails)
        return ApiResponse.ok(
            byEmpNo.map { (k, users) -> UserLookupMatch(k, "EMP_NO", users.map(UserResponse::from)) } +
                byEmail.map { (k, users) -> UserLookupMatch(k, "EMAIL", users.map(UserResponse::from)) },
        )
    }

    @GetMapping("/{subjectId}")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun get(@PathVariable subjectId: Long): ApiResponse<UserResponse> = ApiResponse.ok(UserResponse.from(userService.get(subjectId)))

    /** 관리자 비밀번호 초기화. 잠금도 풀리고, 다음 로그인에서 본인이 바꿔야 한다 (관리자가 계속 알지 않도록) */
    @PostMapping("/{subjectId}/password")
    @RequiresPermission(ApiResources.USER, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun changePassword(@PathVariable subjectId: Long, @Valid @RequestBody request: ChangePasswordRequest): ApiResponse<Unit> {
        val identity = accountService.findLocalIdentity(subjectId) ?: throw NotFoundException("로컬 계정", subjectId)
        accountService.changePassword(identity.requireId(), request.password, requireChangeOnNextLogin = true)
        return ApiResponse.ok(Unit)
    }

    /** 비밀번호·잠금 상태. LOCAL 로그인 계정이 없으면 data 가 null */
    @GetMapping("/{subjectId}/credential")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun credential(@PathVariable subjectId: Long): ApiResponse<CredentialStateResponse?> {
        val identity = accountService.findLocalIdentity(subjectId) ?: return ApiResponse.ok(null)
        return ApiResponse.ok(accountService.findLocalCredential(subjectId)?.let { CredentialStateResponse.from(identity.externalId, it, clock.instant()) })
    }

    /** 로그인 계정이 없는 사용자에게 LOCAL 계정을 만든다. 이미 있으면 409 */
    @PostMapping("/{subjectId}/login-account")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.USER, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun createLoginAccount(@PathVariable subjectId: Long, @Valid @RequestBody request: CreateLoginAccountRequest): ApiResponse<CredentialStateResponse?> {
        userService.get(subjectId)
        accountService.createAccountByAdmin(subjectId, request.loginId.trim(), request.password)
        return credential(subjectId)
    }

    /** 관리자 잠금 해제. 비밀번호는 바꾸지 않는다 */
    @PostMapping("/{subjectId}/unlock")
    @RequiresPermission(ApiResources.USER, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun unlock(@PathVariable subjectId: Long): ApiResponse<Unit> {
        accountService.unlock(subjectId)
        return ApiResponse.ok(Unit)
    }
}

// ---------- 조직 ----------

data class CreateOrganizationRequest(
    @field:NotBlank @field:Size(max = 100) val orgCode: String,
    @field:NotBlank @field:Size(max = 200) val orgName: String,
    val orgType: OrgType,
    val parentOrgId: Long? = null,
)

data class MoveOrganizationRequest(val newParentOrgId: Long)

data class OrganizationResponse(
    val orgId: Long,
    val orgCode: String,
    val orgName: String,
    val orgType: OrgType,
    val parentOrgId: Long?,
    val companyOrgId: Long?,
    val orgLevel: Int,
    val isActive: Boolean,
) {
    companion object {
        fun from(org: Organization) =
            OrganizationResponse(org.requireId(), org.orgCode, org.orgName, org.orgType, org.parentOrgId, org.companyOrgId, org.orgLevel, org.isActive)
    }
}

@RestController
@RequestMapping("/api/v1/organizations")
class OrganizationApi(
    private val organizationService: OrganizationService,
    private val authorizer: AdminAuthorizer,
) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.ORGANIZATION, PermissionAction.CREATE)
    fun create(@Valid @RequestBody request: CreateOrganizationRequest): ApiResponse<OrganizationResponse> =
        ApiResponse.ok(OrganizationResponse.from(organizationService.create(request.orgCode, request.orgName, request.orgType, request.parentOrgId)))

    @GetMapping("/{orgId}")
    @RequiresPermission(ApiResources.ORGANIZATION, PermissionAction.READ, orgOf = OrgTarget.ORG)
    fun get(@PathVariable orgId: Long): ApiResponse<OrganizationResponse> = ApiResponse.ok(OrganizationResponse.from(organizationService.get(orgId)))

    @PostMapping("/{orgId}/move")
    @RequiresPermission(ApiResources.ORGANIZATION, PermissionAction.UPDATE, orgOf = OrgTarget.ORG)
    fun move(@PathVariable orgId: Long, @RequestBody request: MoveOrganizationRequest): ApiResponse<Unit> {
        // 옮길 곳도 범위 안이어야 한다 (조직 단위 관리자가 자기 조직을 범위 밖으로 빼내지 못하게)
        authorizer.requireOrg(ApiResources.ORGANIZATION, PermissionAction.UPDATE, request.newParentOrgId)
        organizationService.move(orgId, request.newParentOrgId)
        return ApiResponse.ok(Unit)
    }
}

// ---------- 소속 ----------

data class JoinRequest(
    val subjectId: Long,
    val orgId: Long,
    val membershipType: MembershipType,
    @field:Size(max = 100) val jobTitle: String? = null,
    @field:Size(max = 100) val jobGrade: String? = null,
    val isManager: Boolean = false,
)

data class TransferRequest(
    val newOrgId: Long,
    @field:Size(max = 100) val jobTitle: String? = null,
    @field:Size(max = 100) val jobGrade: String? = null,
    val isManager: Boolean = false,
)

/** 직위·직급·조직장 여부만 바꾼다. 조직·유형·기간은 그대로다 */
data class UpdateMembershipRequest(
    @field:Size(max = 100) val jobTitle: String? = null,
    @field:Size(max = 100) val jobGrade: String? = null,
    val isManager: Boolean = false,
)

data class MembershipResponse(
    val membershipId: Long,
    val subjectId: Long,
    val orgId: Long,
    val membershipType: MembershipType,
    val jobTitle: String?,
    val jobGrade: String?,
    val isManager: Boolean,
    val validFrom: Instant,
) {
    companion object {
        fun from(m: SubjectOrganization) =
            MembershipResponse(m.requireId(), m.subjectId, m.orgId, m.membershipType, m.jobTitle, m.jobGrade, m.isManager, m.validFrom)
    }
}

@RestController
@RequestMapping("/api/v1")
class MembershipApi(
    private val membershipService: MembershipService,
    private val authorizer: AdminAuthorizer,
) {
    /** 대상 사람과 들어갈 조직이 모두 권한 범위 안이어야 한다 */
    @PostMapping("/memberships")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.CREATE, orgOf = OrgTarget.ANY)
    fun join(@Valid @RequestBody request: JoinRequest): ApiResponse<MembershipResponse> {
        authorizer.requireOrg(ApiResources.MEMBERSHIP, PermissionAction.CREATE, request.orgId)
        authorizer.requireSubject(ApiResources.MEMBERSHIP, PermissionAction.CREATE, request.subjectId)
        return ApiResponse.ok(
            MembershipResponse.from(
                membershipService.join(request.subjectId, request.orgId, request.membershipType, request.jobTitle, request.jobGrade, request.isManager),
            ),
        )
    }

    /** 조직 단위 관리자는 범위 안 소속만, 다른 관리자의 소속은 못 바꾼다 (orgOf = MEMBERSHIP 이 guardAdminTarget 까지 거친다) */
    @PutMapping("/memberships/{membershipId}")
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.UPDATE, orgOf = OrgTarget.MEMBERSHIP)
    fun update(@PathVariable membershipId: Long, @Valid @RequestBody request: UpdateMembershipRequest): ApiResponse<MembershipResponse> =
        ApiResponse.ok(
            MembershipResponse.from(
                membershipService.updateJob(membershipId, request.jobTitle?.trim()?.ifBlank { null }, request.jobGrade?.trim()?.ifBlank { null }, request.isManager),
            ),
        )

    @DeleteMapping("/memberships/{membershipId}")
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.DELETE, orgOf = OrgTarget.MEMBERSHIP)
    fun leave(@PathVariable membershipId: Long): ApiResponse<Unit> {
        membershipService.leave(membershipId)
        return ApiResponse.ok(Unit)
    }

    /** PRIMARY 소속 이동(전적·전보). 전적이면 권한이 정리된다. 지금 조직과 옮길 조직이 모두 권한 범위 안이어야 한다 */
    @PostMapping("/subjects/{subjectId}/primary-membership")
    @RequiresPermission(ApiResources.MEMBERSHIP, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun transfer(@PathVariable subjectId: Long, @Valid @RequestBody request: TransferRequest): ApiResponse<MembershipResponse> {
        authorizer.requireOrg(ApiResources.MEMBERSHIP, PermissionAction.UPDATE, request.newOrgId)
        return ApiResponse.ok(
            MembershipResponse.from(membershipService.transferPrimary(subjectId, request.newOrgId, request.jobTitle, request.jobGrade, request.isManager)),
        )
    }
}

// ---------- 그룹 ----------

data class CreateGroupRequest(
    @field:NotBlank @field:Size(max = 100) val groupCode: String,
    @field:NotBlank @field:Size(max = 200) val groupName: String,
    val groupType: GroupType,
    val ruleExpression: String? = null,
)

data class AddMemberRequest(val subjectId: Long)

data class GroupResponse(
    val groupId: Long, val groupCode: String, val groupName: String, val groupType: GroupType, val ruleExpression: String?, val isActive: Boolean,
) {
    companion object {
        fun from(g: UserGroup) = GroupResponse(g.requireId(), g.groupCode, g.groupName, g.groupType, g.ruleExpression, g.isActive)
    }
}

@RestController
@RequestMapping("/api/v1/groups")
class GroupApi(
    private val groupService: GroupService,
    private val groupMemberService: GroupMemberService,
) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.GROUP, PermissionAction.CREATE)
    fun create(@Valid @RequestBody request: CreateGroupRequest): ApiResponse<GroupResponse> = ApiResponse.ok(
        GroupResponse.from(groupService.create(request.groupCode, request.groupName, request.groupType, request.ruleExpression)),
    )

    @PostMapping("/{groupId}/members")
    @RequiresPermission(ApiResources.GROUP, PermissionAction.UPDATE)
    fun addMember(@PathVariable groupId: Long, @RequestBody request: AddMemberRequest): ApiResponse<Unit> {
        groupMemberService.addMember(groupId, request.subjectId)
        return ApiResponse.ok(Unit)
    }

    @DeleteMapping("/{groupId}/members/{subjectId}")
    @RequiresPermission(ApiResources.GROUP, PermissionAction.UPDATE)
    fun removeMember(@PathVariable groupId: Long, @PathVariable subjectId: Long): ApiResponse<Unit> {
        groupMemberService.removeMember(groupId, subjectId)
        return ApiResponse.ok(Unit)
    }
}
