package com.didrakon.iam.api.support

import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.authz.role.PermissionAction.APPROVE
import com.didrakon.iam.authz.role.PermissionAction.CREATE
import com.didrakon.iam.authz.role.PermissionAction.DELETE
import com.didrakon.iam.authz.role.PermissionAction.EXECUTE
import com.didrakon.iam.authz.role.PermissionAction.READ
import com.didrakon.iam.authz.role.PermissionAction.UPDATE

/**
 * IAM 관리 API 자신의 리소스 목록. 기동 시 [com.didrakon.iam.config.IamBootstrap] 이 RESOURCE·PERMISSION 으로 만들고,
 * 컨트롤러는 [RequiresPermission] 으로 이 키를 가리킨다. IAM 도 자기 PDP 로 판정한다.
 */
object ApiResources {
    /** 관리 콘솔 SSO 클라이언트 코드이자 리소스 트리의 루트 */
    const val CLIENT_CODE = "iam-admin"
    const val ROOT = "iam"

    const val USER = "iam.identity.user"
    const val ORGANIZATION = "iam.identity.organization"
    const val MEMBERSHIP = "iam.identity.membership"
    const val GROUP = "iam.identity.group"
    const val RESOURCE = "iam.authz.resource"
    const val ROLE = "iam.authz.role"
    const val SCOPE = "iam.authz.scope"
    const val ASSIGNMENT = "iam.authz.assignment"
    const val POLICY = "iam.authz.policy"
    const val AUTHZ_CHECK = "iam.authz.check"
    const val ACCESS_REQUEST = "iam.governance.request"
    const val SOD = "iam.governance.sod"
    const val BREAK_GLASS = "iam.governance.breakglass"
    const val DELEGATION = "iam.governance.delegation"
    const val REVIEW = "iam.governance.review"
    const val RISK = "iam.risk.policy"
    const val CLIENT = "iam.authn.client"
    const val SESSION = "iam.authn.session"
    const val API_KEY = "iam.authn.apikey"
    const val AUDIT = "iam.audit.event"
    const val HR_SYNC = "iam.identity.hrsync"
    const val WEBHOOK = "iam.integration.webhook"

    /** 리소스별로 정의할 행위 */
    val CATALOG: Map<String, Set<PermissionAction>> = mapOf(
        USER to setOf(READ, CREATE, UPDATE),
        ORGANIZATION to setOf(READ, CREATE, UPDATE),
        MEMBERSHIP to setOf(READ, CREATE, UPDATE, DELETE),
        GROUP to setOf(READ, CREATE, UPDATE),
        RESOURCE to setOf(READ, CREATE, UPDATE),
        ROLE to setOf(READ, CREATE, UPDATE),
        SCOPE to setOf(READ, CREATE, UPDATE),
        ASSIGNMENT to setOf(READ, CREATE, UPDATE, DELETE),
        POLICY to setOf(READ, CREATE, UPDATE),
        AUTHZ_CHECK to setOf(EXECUTE),
        ACCESS_REQUEST to setOf(READ, APPROVE),
        SOD to setOf(READ, CREATE, UPDATE, APPROVE),
        BREAK_GLASS to setOf(READ, CREATE, UPDATE),
        DELEGATION to setOf(READ, UPDATE),
        REVIEW to setOf(READ, CREATE, APPROVE),
        RISK to setOf(READ, CREATE, UPDATE),
        CLIENT to setOf(READ, CREATE, UPDATE),
        SESSION to setOf(READ, DELETE),
        API_KEY to setOf(READ, CREATE, DELETE),
        AUDIT to setOf(READ),
        HR_SYNC to setOf(EXECUTE, READ),
        WEBHOOK to setOf(READ, CREATE, UPDATE),
    )

    /** JWT 로 권한 판정 API 를 부르는 시스템(client credentials)이 받아야 하는 scope */
    const val AUTHZ_CHECK_SCOPE = "iam.authz.check"

    /** JWT 로 HR 연동 API 를 부르는 인사 시스템(client credentials)이 받아야 하는 scope */
    const val HR_SYNC_SCOPE = "iam.hr.sync"

    fun permissionCode(resourceKey: String, action: PermissionAction) = "$resourceKey:$action"
}

/**
 * 이 API 를 부르려면 IAM 의 PDP 가 (resource, action) 을 허용해야 한다.
 * [scope] 를 지정하면 그 scope 를 가진 클라이언트 토큰은 판정 없이 통과한다 (시스템 간 호출용).
 * [orgOf] 는 판정에 넘길 대상 조직을 어디서 찾는지다. 기본([OrgTarget.NONE])은 대상 조직이 없어 전체 범위 권한만 통과한다.
 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class RequiresPermission(
    val resource: String,
    val action: PermissionAction,
    val scope: String = "",
    val orgOf: OrgTarget = OrgTarget.NONE,
)

/** 로그인한 본인 일을 하는 API (본인 MFA 등록, 본인 접근 요청 등). 사람(subject) 토큰이면 통과한다 */
@Target(AnnotationTarget.FUNCTION)
@Retention(AnnotationRetention.RUNTIME)
annotation class SelfService
