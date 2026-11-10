package com.didrakon.iam.api.authn

import com.didrakon.iam.api.me.MfaMethodResponse
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.OrgTarget
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.apikey.ApiKey
import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.passkey.Passkey
import com.didrakon.iam.authn.passkey.PasskeyService
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.role.PermissionAction
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

/** 사용자의 2단계 인증 수단. 비밀값·공개키는 주지 않는다 */
data class SubjectMfaResponse(val methods: List<MfaMethodResponse>, val passkeys: List<Passkey>)

/** API 키 목록 항목. 키 원문과 hash 는 주지 않는다 */
data class ApiKeyResponse(
    val apiKeyId: Long,
    val keyName: String,
    val issuedAt: Instant,
    val expireAt: Instant?,
    val lastUsedAt: Instant?,
    val revoked: Boolean,
    val revokedAt: Instant?,
) {
    companion object {
        fun from(k: ApiKey) = ApiKeyResponse(k.requireId(), k.keyName, k.issuedAt, k.expireAt, k.lastUsedAt, k.revoked, k.revokedAt)
    }
}

data class RevokedSessionsResponse(val revokedSessions: Int)

/**
 * 헬프데스크 일: 사용자의 2단계 인증 수단 조회·초기화, API 키 목록, 모든 로그인 세션 끊기.
 * 대상이 경로의 사람이므로 조직 단위 관리자는 범위 안 사람에게만 쓰고, 다른 관리자는 바꿀 수 없다 (guardAdminTarget)
 */
@RestController
@RequestMapping("/api/v1/subjects/{subjectId}")
class AccountAdminApi(
    private val mfaService: MfaService,
    private val passkeyService: PasskeyService,
    private val apiKeyService: ApiKeyService,
    private val sessionService: LoginSessionService,
) {
    @GetMapping("/mfa")
    @RequiresPermission(ApiResources.USER, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun mfa(@PathVariable subjectId: Long) = ApiResponse.ok(
        SubjectMfaResponse(mfaService.verifiedMethods(subjectId).map(MfaMethodResponse::from), passkeyService.list(subjectId)),
    )

    /** 인증 앱 초기화 (기기 분실). 그 사람의 로그인 세션과 발급한 토큰도 함께 끝낸다 */
    @DeleteMapping("/mfa/{methodId}")
    @RequiresPermission(ApiResources.USER, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun removeMfa(@PathVariable subjectId: Long, @PathVariable methodId: Long): ApiResponse<Unit> {
        mfaService.removeByAdmin(subjectId, methodId)
        return ApiResponse.ok(Unit)
    }

    @DeleteMapping("/mfa/passkeys/{credentialId}")
    @RequiresPermission(ApiResources.USER, PermissionAction.UPDATE, orgOf = OrgTarget.SUBJECT)
    fun removePasskey(@PathVariable subjectId: Long, @PathVariable credentialId: String): ApiResponse<Unit> {
        passkeyService.removeByAdmin(subjectId, credentialId)
        return ApiResponse.ok(Unit)
    }

    /** 폐기·만료된 키도 함께 보여준다. 최근 발급 순 */
    @GetMapping("/api-keys")
    @RequiresPermission(ApiResources.API_KEY, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun apiKeys(@PathVariable subjectId: Long) = ApiResponse.ok(apiKeyService.list(subjectId).map(ApiKeyResponse::from))

    /** 모든 로그인 세션을 끝내고 발급한 토큰을 회수한다 (계정 탈취 의심 등) */
    @DeleteMapping("/sessions")
    @RequiresPermission(ApiResources.SESSION, PermissionAction.DELETE, orgOf = OrgTarget.SUBJECT)
    fun revokeAllSessions(@PathVariable subjectId: Long) =
        ApiResponse.ok(RevokedSessionsResponse(sessionService.revokeAllByAdmin(subjectId)))
}
