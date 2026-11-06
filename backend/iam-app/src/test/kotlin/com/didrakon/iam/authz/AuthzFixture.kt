package com.didrakon.iam.authz

import com.didrakon.iam.authz.resource.Resource
import com.didrakon.iam.authz.resource.ResourceRepository
import com.didrakon.iam.authz.resource.ResourceType
import com.didrakon.iam.authz.resource.Sensitivity
import com.didrakon.iam.authz.role.Permission
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionEffect
import com.didrakon.iam.authz.role.PermissionRepository
import com.didrakon.iam.authz.role.Role
import com.didrakon.iam.authz.role.RolePermission
import com.didrakon.iam.authz.role.RolePermissionRepository
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.role.RoleType
import com.didrakon.iam.authz.scope.Scope
import com.didrakon.iam.authz.scope.ScopeRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.identity.organization.MembershipService
import com.didrakon.iam.identity.organization.MembershipType
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Clock
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

/** authz 통합 테스트용 데이터 생성기. 테스트 트랜잭션이 롤백하므로 정리하지 않는다 */
class AuthzFixture(
    private val jdbc: JdbcTemplate,
    private val userRepository: UserRepository,
    private val organizationService: OrganizationService,
    private val membershipService: MembershipService,
    private val resourceRepository: ResourceRepository,
    private val roleRepository: RoleRepository,
    private val permissionRepository: PermissionRepository,
    private val rolePermissionRepository: RolePermissionRepository,
    private val scopeRepository: ScopeRepository,
    private val clock: Clock,
) {
    private val sequence = AtomicLong()

    fun user(name: String = "사용자"): Long = userRepository.save(User(code("E"), name)).requireId()

    fun org(type: OrgType, parentId: Long? = null): Long = organizationService.create(code(type.name), type.name, type, parentId).requireId()

    fun join(subjectId: Long, orgId: Long, type: MembershipType = MembershipType.PRIMARY) {
        membershipService.join(subjectId, orgId, type)
    }

    /** resource 는 SSO 클라이언트에 속하므로 SAS 클라이언트와 SSO 클라이언트를 함께 만든다 (authn 엔티티는 아직 없음) */
    fun client(): Long {
        val registeredId = UUID.randomUUID().toString()
        jdbc.update(
            """
            INSERT INTO oauth2_registered_client (id, client_id, client_name, client_authentication_methods,
                authorization_grant_types, scopes, client_settings, token_settings)
            VALUES (?, ?, 'test', 'client_secret_basic', 'authorization_code', 'openid', '{}', '{}')
            """,
            registeredId, registeredId,
        )
        jdbc.update(
            """
            INSERT INTO sso_client (registered_client_id, client_code, client_name, client_type, protocol, created_at)
            VALUES (?, ?, 'test', 'WEB', 'OIDC', NOW(6))
            """,
            registeredId, code("CLIENT"),
        )
        return jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long::class.java) ?: throw IllegalStateException("client 생성 실패")
    }

    fun resource(
        clientId: Long = client(),
        parentId: Long? = null,
        sensitivity: Sensitivity = Sensitivity.INTERNAL,
        type: ResourceType = ResourceType.API,
    ): Resource = resourceRepository.save(Resource(clientId, code("res"), "리소스", type, sensitivity, parentId))

    fun role(): Role = roleRepository.save(Role(code("ROLE"), "역할", RoleType.BUSINESS))

    fun permission(resourceId: Long, action: PermissionAction = PermissionAction.READ, effect: PermissionEffect = PermissionEffect.ALLOW): Permission =
        permissionRepository.save(Permission(code("PERM"), "권한", resourceId, action, effect))

    fun grant(roleId: Long, permissionId: Long, scopeId: Long = globalScopeId()): RolePermission =
        rolePermissionRepository.save(RolePermission(roleId, permissionId, scopeId, clock.instant().minusSeconds(60)))

    /** 리소스에 READ 권한을 만들고 그 권한을 가진 역할을 만든다 */
    fun roleAllowing(resourceId: Long, action: PermissionAction = PermissionAction.READ, effect: PermissionEffect = PermissionEffect.ALLOW): Role {
        val role = role()
        grant(role.requireId(), permission(resourceId, action, effect).requireId())
        return role
    }

    fun orgScope(orgId: Long, includeDescendants: Boolean = true): Scope =
        scopeRepository.save(Scope(code("SCOPE"), "조직 범위", ScopeType.ORGANIZATION, orgId = orgId, includeDescendants = includeDescendants))

    fun resourceScope(resourceId: Long, includeDescendants: Boolean = true): Scope =
        scopeRepository.save(Scope(code("SCOPE"), "리소스 범위", ScopeType.RESOURCE, resourceId = resourceId, includeDescendants = includeDescendants))

    fun globalScopeId(): Long = scopeRepository.findByScopeCode(Scope.GLOBAL_CODE)?.requireId() ?: throw IllegalStateException("GLOBAL scope 없음")

    private fun code(prefix: String) = "$prefix-${sequence.incrementAndGet()}-${System.nanoTime()}"
}
