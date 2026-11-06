package com.didrakon.iam.api.authn

import com.didrakon.iam.api.support.ApiPrincipal
import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.api.support.ApiResponse
import com.didrakon.iam.api.support.OrgTarget
import com.didrakon.iam.api.support.RequiresPermission
import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.session.LoginSession
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.role.PermissionAction
import jakarta.validation.Valid
import jakarta.validation.constraints.NotBlank
import jakarta.validation.constraints.Size
import org.springframework.http.HttpStatus
import org.springframework.web.bind.annotation.DeleteMapping
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.PostMapping
import org.springframework.web.bind.annotation.RequestBody
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.ResponseStatus
import org.springframework.web.bind.annotation.RestController
import java.time.Instant

data class RegisterClientRequest(
    @field:NotBlank @field:Size(max = 100) val clientCode: String,
    @field:NotBlank @field:Size(max = 200) val clientName: String,
    val clientType: ClientType,
    val redirectUris: Set<String> = emptySet(),
    val postLogoutRedirectUris: Set<String> = emptySet(),
    val scopes: Set<String> = emptySet(),
    val confidential: Boolean = true,
    val requireMfa: Boolean = false,
    @field:Size(max = 500) val backchannelLogoutUri: String? = null,
    /** 토큰에 role = "authenticated" 를 넣는다 (Supabase Third-Party Auth) */
    val supabaseRoleClaim: Boolean = false,
    /** 앱 런처 시작 주소. 있으면 IAM 홈의 내 앱 목록에 나온다 */
    @field:Size(max = 500) val homeUrl: String? = null,
)

/** clientSecret 은 이 응답에서 한 번만 보여준다 */
data class RegisteredClientResponse(val ssoClientId: Long, val clientId: String, val clientSecret: String?)

@RestController
@RequestMapping("/api/v1/clients")
class ClientApi(private val clientService: SsoClientService) {
    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.CLIENT, PermissionAction.CREATE)
    fun register(@Valid @RequestBody r: RegisterClientRequest): ApiResponse<RegisteredClientResponse> {
        val result = clientService.register(
            ClientRegistration(
                r.clientCode, r.clientName, r.clientType, r.redirectUris, r.postLogoutRedirectUris, r.scopes, r.confidential, r.requireMfa,
                r.backchannelLogoutUri, r.supabaseRoleClaim, r.homeUrl,
            ),
        )
        return ApiResponse.ok(RegisteredClientResponse(result.ssoClient.requireId(), result.clientId, result.clientSecret))
    }
}

data class LoginSessionResponse(
    val sessionId: Long,
    val authenticationLevel: String,
    val ipAddress: String?,
    val loginAt: Instant,
    val expireAt: Instant,
) {
    companion object {
        fun from(s: LoginSession) = LoginSessionResponse(s.requireId(), s.authenticationLevel.name, s.ipAddress, s.loginAt, s.expireAt)
    }
}

data class IssueApiKeyRequest(@field:NotBlank @field:Size(max = 200) val keyName: String, val expireAt: Instant? = null)

/** rawKey 는 이 응답에서 한 번만 보여준다 */
data class IssuedApiKeyResponse(val apiKeyId: Long, val rawKey: String, val expireAt: Instant?)

@RestController
@RequestMapping("/api/v1")
class CredentialApi(
    private val sessionService: LoginSessionService,
    private val apiKeyService: ApiKeyService,
) {
    @GetMapping("/subjects/{subjectId}/sessions")
    @RequiresPermission(ApiResources.SESSION, PermissionAction.READ, orgOf = OrgTarget.SUBJECT)
    fun sessions(@PathVariable subjectId: Long) = ApiResponse.ok(sessionService.activeSessions(subjectId).map(LoginSessionResponse::from))

    /** 강제 로그아웃. 해당 브라우저의 다음 요청부터 적용된다 */
    @DeleteMapping("/sessions/{sessionId}")
    @RequiresPermission(ApiResources.SESSION, PermissionAction.DELETE, orgOf = OrgTarget.SESSION)
    fun revokeSession(@PathVariable sessionId: Long): ApiResponse<Unit> {
        sessionService.revoke(sessionId)
        return ApiResponse.ok(Unit)
    }

    @PostMapping("/subjects/{subjectId}/api-keys")
    @ResponseStatus(HttpStatus.CREATED)
    @RequiresPermission(ApiResources.API_KEY, PermissionAction.CREATE)
    fun issueApiKey(@PathVariable subjectId: Long, @Valid @RequestBody r: IssueApiKeyRequest): ApiResponse<IssuedApiKeyResponse> {
        val issued = apiKeyService.issue(subjectId, r.keyName, r.expireAt)
        return ApiResponse.ok(IssuedApiKeyResponse(issued.apiKey.requireId(), issued.rawKey, issued.apiKey.expireAt))
    }

    @DeleteMapping("/api-keys/{apiKeyId}")
    @RequiresPermission(ApiResources.API_KEY, PermissionAction.DELETE)
    fun revokeApiKey(@PathVariable apiKeyId: Long): ApiResponse<Unit> {
        apiKeyService.revoke(apiKeyId, ApiPrincipal.subjectId())
        return ApiResponse.ok(Unit)
    }
}
