package com.didrakon.iam.api

import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.RequestPostProcessor
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** 본인 2단계 인증 수단 등록·조회·삭제. 테스트마다 롤백된다 */
@AuthzTest
class MeMfaApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val accountService: LocalAccountService,
    private val methodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val apiKeyService: ApiKeyService,
) {
    @Test
    fun `확인을 마친 수단만 목록에 나오고, 새 등록을 시작하면 확인 안 된 이전 등록은 지워진다`() {
        val subjectId = fixture.user()
        val loginId = "mfa${System.nanoTime()}"
        accountService.createAccount(subjectId, loginId, "correct-horse-battery")

        val first = enroll(subjectId)
        mockMvc.perform(get("/api/v1/me/mfa").with(user(subjectId))).andExpect(jsonPath("$.data.length()").value(0))
        assertTrue(first.second.contains(loginId), "인증 앱 계정 이름은 로그인 ID: ${first.second}")

        val second = enroll(subjectId)
        assertEquals(listOf(second.first), methodRepository.findBySubjectId(subjectId).map { it.requireId() })

        confirm(subjectId, second.first)
        mockMvc.perform(get("/api/v1/me/mfa").with(user(subjectId)))
            .andExpect(jsonPath("$.data.length()").value(1))
            .andExpect(jsonPath("$.data[0].methodId").value(second.first))
            .andExpect(jsonPath("$.data[0].lastUsedAt").exists())

        // 확인을 마친 수단은 새 등록을 시작해도 남는다 (휴대폰 교체 중 잠기지 않게). 이제 MFA 가 있으니 MFA 로그인으로 한다
        enroll(subjectId, mfaUser(subjectId))
        mockMvc.perform(get("/api/v1/me/mfa").with(user(subjectId))).andExpect(jsonPath("$.data.length()").value(1))

        mockMvc.perform(delete("/api/v1/me/mfa/${second.first}").with(mfaUser(subjectId))).andExpect(status().isOk)
        mockMvc.perform(get("/api/v1/me/mfa").with(user(subjectId))).andExpect(jsonPath("$.data.length()").value(0))
    }

    @Test
    fun `MFA 가 이미 있으면 비밀번호만으로 로그인한 토큰으로는 수단을 더하거나 지울 수 없다`() {
        val subjectId = fixture.user()
        accountService.createAccount(subjectId, "mfa${System.nanoTime()}", "correct-horse-battery")
        val existing = enroll(subjectId).first
        confirm(subjectId, existing)

        mockMvc.perform(post("/api/v1/me/mfa/totp").with(user(subjectId)))
            .andExpect(status().isUnauthorized).andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))
        mockMvc.perform(delete("/api/v1/me/mfa/$existing").with(user(subjectId)))
            .andExpect(status().isUnauthorized).andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))
        mockMvc.perform(delete("/api/v1/me/passkeys/unknown-credential").with(user(subjectId)))
            .andExpect(status().isUnauthorized).andExpect(jsonPath("$.error.code").value("MFA_REQUIRED"))

        // 패스키로 로그인한 토큰(hwk)도 MFA 로 본다
        val withPasskey = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("hwk", "user")) }
        mockMvc.perform(post("/api/v1/me/mfa/totp").with(withPasskey)).andExpect(status().isCreated)
    }

    @Test
    fun `API 키로는 2단계 인증 수단을 등록·확인·삭제할 수 없다`() {
        val subjectId = fixture.user()
        accountService.createAccount(subjectId, "mfa${System.nanoTime()}", "correct-horse-battery")
        val apiKey = apiKeyService.issue(subjectId, "배치").rawKey

        mockMvc.perform(post("/api/v1/me/mfa/totp").header("X-API-Key", apiKey)).andExpect(status().isForbidden)
        mockMvc.perform(
            post("/api/v1/me/mfa/totp/1/confirm").header("X-API-Key", apiKey).contentType(MediaType.APPLICATION_JSON).content("""{"code":"123456"}"""),
        ).andExpect(status().isForbidden)
        mockMvc.perform(delete("/api/v1/me/mfa/1").header("X-API-Key", apiKey)).andExpect(status().isForbidden)
        mockMvc.perform(delete("/api/v1/me/passkeys/x").header("X-API-Key", apiKey)).andExpect(status().isForbidden)
        assertEquals(emptyList(), methodRepository.findBySubjectId(subjectId))
    }

    @Test
    fun `본인 비밀번호는 현재 비밀번호를 맞혀야 바꿀 수 있다`() {
        val subjectId = fixture.user()
        accountService.createAccount(subjectId, "pw${System.nanoTime()}", "correct-horse-battery")

        mockMvc.perform(
            post("/api/v1/me/password").with(user(subjectId)).contentType(MediaType.APPLICATION_JSON)
                .content("""{"currentPassword":"wrong-one-123","newPassword":"another-secret-9"}"""),
        ).andExpect(status().is4xxClientError)
        mockMvc.perform(
            post("/api/v1/me/password").with(user(subjectId)).contentType(MediaType.APPLICATION_JSON)
                .content("""{"currentPassword":"correct-horse-battery","newPassword":"another-secret-9"}"""),
        ).andExpect(status().isOk)
    }

    /** (methodId, otpauth URI) */
    private fun enroll(subjectId: Long, token: RequestPostProcessor = user(subjectId)): Pair<Long, String> {
        val body = mockMvc.perform(post("/api/v1/me/mfa/totp").with(token)).andExpect(status().isCreated).andReturn().response.contentAsString
        val methodId = Regex("\"methodId\":(\\d+)").find(body)?.groupValues?.get(1)?.toLong() ?: throw AssertionError(body)
        val uri = Regex("\"otpauthUri\":\"([^\"]+)\"").find(body)?.groupValues?.get(1) ?: throw AssertionError(body)
        return methodId to uri
    }

    private fun confirm(subjectId: Long, methodId: Long) {
        val reference = methodRepository.findById(methodId).orElseThrow().secretReference ?: throw AssertionError()
        val code = Totp.code(secretStore.load(reference), Instant.now())
        mockMvc.perform(
            post("/api/v1/me/mfa/totp/$methodId/confirm").with(user(subjectId)).contentType(MediaType.APPLICATION_JSON).content("""{"code":"$code"}"""),
        ).andExpect(status().isOk)
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd")) }

    private fun mfaUser(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
