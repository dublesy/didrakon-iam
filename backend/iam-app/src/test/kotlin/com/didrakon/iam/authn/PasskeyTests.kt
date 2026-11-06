package com.didrakon.iam.authn

import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.RegisteredClientResult
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.login.AuthFactors
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authn.passkey.PasskeyService
import com.didrakon.iam.authn.session.AuthenticationLevel
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import com.didrakon.iam.risk.RiskAction
import com.didrakon.iam.risk.RiskPolicy
import com.didrakon.iam.risk.RiskPolicyRepository
import com.didrakon.iam.risk.RiskType
import org.hamcrest.Matchers.containsString
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.core.context.SecurityContext
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.security.web.context.HttpSessionSecurityContextRepository
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.content
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.model
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.net.URI
import java.time.Instant
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * 패스키(WebAuthn) 등록·로그인을 가상 인증기(webauthn4j-test)로 끝까지 확인한다.
 * 요청마다 커밋되어야 로그인 처리와 같은 조건이 되므로 롤백하지 않는다.
 */
@IntegrationTest
class PasskeyTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val mfaService: MfaService,
    private val mfaMethodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val passkeyService: PasskeyService,
    private val userService: UserService,
    private val clientService: SsoClientService,
    private val riskPolicyRepository: RiskPolicyRepository,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
    private val jsonMapper: JsonMapper,
) {
    private val password = "correct-horse-battery"
    private val callback = "https://app.example.com/callback"

    @Test
    fun `2단계 인증을 거친 세션에서 패스키를 등록하면 목록과 감사 기록에 남는다`() {
        val user = mfaUser()
        val session = mfaLogin(user)
        mockMvc.perform(get("/account/passkeys").session(session))
            .andExpect(status().isOk).andExpect(model().attribute("canManage", true))

        register(session, VirtualPasskey()).andExpect(status().isOk).andExpect(jsonPath("$.success").value(true))

        assertEquals(listOf("업무용 노트북"), passkeyService.list(user.id).map { it.label })
        assertEquals(1, audits(user.id, "PASSKEY_ADD"))
        // WebAuthn 사용자 이름은 subject ID 다
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM user_entities WHERE name = ?", Int::class.java, user.id.toString()))
    }

    @Test
    fun `비밀번호만 거친 세션으로는 패스키를 등록할 수 없다`() {
        val user = account()
        val session = passwordLogin(user).first

        mockMvc.perform(post("/webauthn/register/options").session(session).with(csrf())).andExpect(status().isForbidden)
        // 경로를 인코딩해도 같은 등록 요청이다 (Spring 의 등록 필터는 디코딩한 경로로 맞춘다)
        mockMvc.perform(post(URI.create("/webauthn/%72egister/options")).session(session).with(csrf())).andExpect(status().isForbidden)
        mockMvc.perform(post(URI.create("/webauthn/register/%6Fptions")).session(session).with(csrf())).andExpect(status().isForbidden)
        mockMvc.perform(get("/account/passkeys").session(session))
            .andExpect(status().isOk).andExpect(model().attribute("canManage", false))
        mockMvc.perform(post("/webauthn/register/options").with(csrf())).andExpect(status().isUnauthorized)
    }

    @Test
    fun `로그인 전에 패스키 화면을 열면 로그인 뒤 그 화면으로 돌아오고, 인증 앱이 있으면 코드를 거친다`() {
        val user = mfaUser()
        val session = MockHttpSession()
        mockMvc.perform(get("/account/passkeys").session(session).accept(MediaType.TEXT_HTML)).andExpect(status().is3xxRedirection)

        mockMvc.perform(post("/login").param("username", user.loginId).param("password", password).session(session).with(csrf()))
            .andExpect(redirectedUrl("/login/mfa"))
        val back = mockMvc.perform(post("/login/mfa").param("code", nextCode(user)).session(session).with(csrf()))
            .andReturn().response.redirectedUrl ?: throw AssertionError("redirect 없음")

        assertTrue(back.endsWith("/account/passkeys?continue"), back)
        mockMvc.perform(get(back).session(session)).andExpect(status().isOk).andExpect(model().attribute("canManage", true))
    }

    @Test
    fun `비밀번호로만 로그인한 뒤 인증 앱을 등록했으면 패스키 화면이 인증 앱 코드를 받고 돌아온다`() {
        val user = account()
        val session = passwordLogin(user).first
        val secret = enrollTotp(user.id, user.loginId)

        mockMvc.perform(get("/account/passkeys").session(session)).andExpect(redirectedUrl("/login/mfa"))
        val back = mockMvc.perform(post("/login/mfa").param("code", Totp.code(secret, Instant.now().plusSeconds(30))).session(session).with(csrf()))
            .andReturn().response.redirectedUrl ?: throw AssertionError("redirect 없음")

        assertTrue(back.endsWith("/account/passkeys?continue"), back)
    }

    @Test
    fun `패스키로 로그인하면 MFA 수준 세션이 열리고 비밀번호 실패 횟수는 건드리지 않는다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        jdbc.update("UPDATE local_credential SET failed_attempt_count = 2 WHERE identity_id = ?", identityId(user))
        val session = MockHttpSession()

        passkeyLogin(device, session)
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.authenticated").value(true))
            .andExpect(jsonPath("$.redirectUrl").value("/"))

        val authentication = (session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY) as SecurityContext).authentication
            ?: throw AssertionError("인증 정보 없음")
        assertEquals(user.id.toString(), authentication.name)
        assertEquals(listOf(AuthFactors.WEBAUTHN), authentication.authorities.map { it.authority })
        assertNotNull(session.getAttribute(AuthFactors.LOGIN_SESSION_KEY))
        assertEquals(null, session.getAttribute(AuthFactors.MFA_PENDING))
        assertTrue(AuthenticationLevel.MFA in sessionService.activeSessions(user.id).map { it.authenticationLevel })
        assertEquals(1, events(user.id, "LOGIN", "SUCCESS", "PASSKEY"))
        assertEquals(2, failedAttempts(user))
        assertNotNull(passkeyService.list(user.id).single().lastUsedAt)
        // 인증 앱 코드를 다시 묻지 않고 IAM 화면에 들어간다
        mockMvc.perform(get("/").session(session)).andExpect(status().isOk)
    }

    @Test
    fun `2단계 인증 수단이 패스키뿐이면 비밀번호만으로는 로그인할 수 없고 패스키로는 된다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        mfaService.verifiedMethods(user.id).forEach { mfaService.remove(user.id, it.requireId()) }

        val (session, result) = passwordLogin(user)
        result.andExpect(redirectedUrl("/login?passkey-required"))
        assertEquals(null, session.getAttribute(AuthFactors.LOGIN_SESSION_KEY))
        assertEquals(1, events(user.id, "LOGIN", "FAILURE", "PASSKEY_REQUIRED"))
        assertEquals(0, failedAttempts(user), "비밀번호는 맞았으므로 실패 횟수에 넣지 않는다")
        mockMvc.perform(get("/login").param("passkey-required", "")).andExpect(content().string(containsString("패스키로 로그인합니다")))

        passkeyLogin(device).andExpect(status().isOk).andExpect(jsonPath("$.authenticated").value(true))
    }

    @Test
    fun `같은 패스키 응답을 다시 보내면 거부하고 실패 기록만 남긴다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        jdbc.update("UPDATE local_credential SET failed_attempt_count = 2 WHERE identity_id = ?", identityId(user))
        val session = MockHttpSession()
        val body = device.authenticate(options(session, "/webauthn/authenticate/options"))
        mockMvc.perform(post("/login/webauthn").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isOk)

        val replay = MockHttpSession()
        options(replay, "/webauthn/authenticate/options")
        mockMvc.perform(post("/login/webauthn").session(replay).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.redirectUrl").value("/login?passkey"))

        assertEquals(2, failedAttempts(user))
        assertTrue((jdbc.queryForObject("SELECT COUNT(*) FROM authentication_event WHERE event_type = 'FAILED_LOGIN' AND failure_reason LIKE 'PASSKEY:%'", Int::class.java) ?: 0) > 0)
    }

    @Test
    fun `사용 안 함 계정은 패스키로 로그인할 수 없다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        userService.changeStatus(user.id, SubjectStatus.DISABLED)

        passkeyLogin(device)
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.authenticated").value(false))
            .andExpect(jsonPath("$.redirectUrl").value("/login?unavailable"))

        assertEquals(1, events(user.id, "FAILED_LOGIN", "FAILURE", "PASSKEY: PasskeyAccountUnavailableException"))
        assertEquals(emptyList(), sessionService.activeSessions(user.id))
    }

    @Test
    fun `비밀번호 실패로 일시 잠긴 동안은 패스키로도 로그인할 수 없고 잠금이 풀리면 된다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        jdbc.update("UPDATE local_credential SET failed_attempt_count = 5, locked_until = '2999-01-01 00:00:00' WHERE identity_id = ?", identityId(user))
        val sessionsBefore = sessionService.activeSessions(user.id).size

        passkeyLogin(device)
            .andExpect(status().isUnauthorized)
            .andExpect(jsonPath("$.redirectUrl").value("/login?unavailable"))
        assertEquals(1, events(user.id, "FAILED_LOGIN", "FAILURE", "PASSKEY: PasskeyAccountUnavailableException"))
        assertEquals(sessionsBefore, sessionService.activeSessions(user.id).size, "새 로그인 세션을 열지 않는다")

        jdbc.update("UPDATE local_credential SET locked_until = '2000-01-01 00:00:00' WHERE identity_id = ?", identityId(user))
        passkeyLogin(device).andExpect(status().isOk).andExpect(jsonPath("$.authenticated").value(true))
    }

    @Test
    fun `위험 평가가 DENY 면 패스키로도 막고, CHALLENGE 는 패스키로 충족한 것으로 기록한다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)

        withRiskPolicy(90, RiskAction.ALLOW) {
            passkeyLogin(device).andExpect(status().isForbidden).andExpect(jsonPath("$.redirectUrl").value("/login?risk"))
        }
        assertEquals(1, events(user.id, "LOGIN", "FAILURE", "RISK_DENIED%"))

        withRiskPolicy(30, RiskAction.CHALLENGE) {
            passkeyLogin(device).andExpect(status().isOk).andExpect(jsonPath("$.authenticated").value(true))
        }
        assertEquals(1, events(user.id, "LOGIN", "CHALLENGE", "RISK_CHALLENGE:%패스키로 충족"))
    }

    @Test
    fun `패스키 로그인 토큰의 amr 은 hwk·user 이고 refresh 해도 유지되며 MFA 필수 클라이언트도 통과한다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        register(mfaLogin(user), device).andExpect(status().isOk)
        val session = MockHttpSession()
        passkeyLogin(device, session).andExpect(status().isOk)
        val client = webClient(requireMfa = true)

        val location = authorizeRequest(client, session).andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl
            ?: throw AssertionError("redirect 없음")
        assertTrue(location.startsWith(callback), location)
        val code = UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code") ?: throw AssertionError("code 없음")
        val tokens = json(token(client, "grant_type" to "authorization_code", "code" to code, "redirect_uri" to callback).andExpect(status().isOk))

        val claims = payload(tokens["access_token"].stringValue())
        assertEquals(user.id.toString(), claims["sub"].stringValue())
        assertEquals(listOf("hwk", "user"), claims["amr"].values().map { it.stringValue() })
        val refreshed = json(token(client, "grant_type" to "refresh_token", "refresh_token" to tokens["refresh_token"].stringValue()).andExpect(status().isOk))
        assertEquals(listOf("hwk", "user"), payload(refreshed["access_token"].stringValue())["amr"].values().map { it.stringValue() })
    }

    @Test
    fun `본인 패스키를 콘솔 API 로 조회·삭제하고 남의 패스키는 지울 수 없다`() {
        val user = mfaUser()
        register(mfaLogin(user), VirtualPasskey()).andExpect(status().isOk)
        val other = mfaUser()
        register(mfaLogin(other), VirtualPasskey()).andExpect(status().isOk)
        val credentialId = passkeyService.list(user.id).single().credentialId

        mockMvc.perform(get("/api/v1/me/passkeys").with(token(user.id)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[0].credentialId").value(credentialId))
            .andExpect(jsonPath("$.data[0].label").value("업무용 노트북"))
        mockMvc.perform(delete("/api/v1/me/passkeys/$credentialId").with(token(other.id))).andExpect(status().isNotFound)
        mockMvc.perform(delete("/api/v1/me/passkeys/$credentialId").with(token(user.id))).andExpect(status().isOk)

        assertEquals(emptyList(), passkeyService.list(user.id))
        assertEquals(1, passkeyService.list(other.id).size)
        assertEquals(1, audits(user.id, "PASSKEY_REMOVE"))
    }

    @Test
    fun `IAM 패스키 화면에서 삭제하면 그 패스키로는 로그인할 수 없다`() {
        val user = mfaUser()
        val device = VirtualPasskey()
        val session = mfaLogin(user)
        register(session, device).andExpect(status().isOk)
        val credentialId = passkeyService.list(user.id).single().credentialId

        mockMvc.perform(post("/account/passkeys/$credentialId/delete").session(session).with(csrf()))
            .andExpect(redirectedUrl("/account/passkeys?removed"))

        passkeyLogin(device).andExpect(status().isUnauthorized)
    }

    private data class TestUser(val id: Long, val loginId: String, val totpSecret: ByteArray?)

    private fun account(): TestUser {
        val userId = fixture.user()
        val loginId = "passkey${System.nanoTime()}"
        accountService.createAccount(userId, loginId, password)
        return TestUser(userId, loginId, null)
    }

    private fun mfaUser(): TestUser = account().let { it.copy(totpSecret = enrollTotp(it.id, it.loginId)) }

    private fun enrollTotp(userId: Long, loginId: String): ByteArray {
        val enrollment = mfaService.enrollTotp(userId, loginId)
        val reference = mfaMethodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        val secret = secretStore.load(reference)
        mfaService.confirmTotp(userId, enrollment.methodId, Totp.code(secret, Instant.now()))
        return secret
    }

    /** 등록 확인에 쓴 구간의 코드는 재사용 방지로 거부되므로 다음 구간의 코드를 쓴다 */
    private fun nextCode(user: TestUser) = Totp.code(user.totpSecret ?: throw AssertionError("인증 앱 없음"), Instant.now().plusSeconds(30))

    private fun passwordLogin(user: TestUser): Pair<MockHttpSession, ResultActions> {
        val session = MockHttpSession()
        val result = mockMvc.perform(post("/login").param("username", user.loginId).param("password", password).session(session).with(csrf()))
        return session to result
    }

    private fun mfaLogin(user: TestUser): MockHttpSession {
        val (session, result) = passwordLogin(user)
        result.andExpect(redirectedUrl("/login/mfa"))
        mockMvc.perform(post("/login/mfa").param("code", nextCode(user)).session(session).with(csrf())).andExpect(redirectedUrl("/"))
        return session
    }

    private fun options(session: MockHttpSession, path: String): JsonNode =
        json(mockMvc.perform(post(path).session(session).with(csrf())).andExpect(status().isOk))

    private fun register(session: MockHttpSession, device: VirtualPasskey): ResultActions {
        val body = device.register(options(session, "/webauthn/register/options"), "업무용 노트북")
        return mockMvc.perform(post("/webauthn/register").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
    }

    private fun passkeyLogin(device: VirtualPasskey, session: MockHttpSession = MockHttpSession()): ResultActions {
        val body = device.authenticate(options(session, "/webauthn/authenticate/options"))
        return mockMvc.perform(post("/login/webauthn").session(session).with(csrf()).contentType(MediaType.APPLICATION_JSON).content(body))
    }

    /** 다른 테스트에 영향이 없도록 끝나면 끈다. 시각과 무관하게 늘 잡히는 조건이다 */
    private fun withRiskPolicy(score: Int, action: RiskAction, block: () -> Unit) {
        val policy = riskPolicyRepository.save(RiskPolicy("패스키 테스트 $score", RiskType.LOGIN, ALWAYS, score, action))
        try {
            block()
        } finally {
            jdbc.update("UPDATE risk_policy SET is_active = FALSE WHERE risk_policy_id = ?", policy.requireId())
        }
    }

    private fun webClient(requireMfa: Boolean): RegisteredClientResult =
        clientService.register(
            ClientRegistration("web-${System.nanoTime()}", "웹", ClientType.WEB, redirectUris = setOf(callback), requireMfa = requireMfa),
        )

    private fun authorizeRequest(client: RegisteredClientResult, session: MockHttpSession) =
        mockMvc.perform(
            get(
                UriComponentsBuilder.fromPath("/oauth2/authorize")
                    .queryParam("response_type", "code").queryParam("client_id", client.clientId)
                    .queryParam("redirect_uri", callback).queryParam("scope", "openid").queryParam("state", "state-1")
                    .encode().build().toUriString(),
            ).session(session),
        )

    private fun token(client: RegisteredClientResult, vararg params: Pair<String, String>) =
        mockMvc.perform(
            post("/oauth2/token").with(httpBasic(client.clientId, client.clientSecret ?: throw AssertionError("비밀값 없음")))
                .apply { params.forEach { (k, v) -> param(k, v) } },
        )

    /** 콘솔이 쓰는 IAM 토큰과 같은 모양 */
    private fun token(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("hwk", "user")) }

    private fun identityId(user: TestUser) = accountService.findLocalIdentity(user.id)?.requireId() ?: throw AssertionError()

    private fun failedAttempts(user: TestUser): Int? =
        jdbc.queryForObject("SELECT failed_attempt_count FROM local_credential WHERE identity_id = ?", Int::class.java, identityId(user))

    private fun events(subjectId: Long, type: String, result: String, reasonPattern: String): Int? =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM authentication_event WHERE subject_id = ? AND event_type = ? AND result = ? AND failure_reason LIKE ?",
            Int::class.java, subjectId, type, result, reasonPattern,
        )

    private fun audits(subjectId: Long, action: String): Int? =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM audit_event WHERE target_subject_id = ? AND resource_type = 'PASSKEY' AND action = ?",
            Int::class.java, subjectId, action,
        )

    private fun json(result: ResultActions): JsonNode = jsonMapper.readTree(result.andReturn().response.contentAsString)

    private fun payload(jwt: String): JsonNode = jsonMapper.readTree(Base64.getUrlDecoder().decode(jwt.split(".")[1]))

    companion object {
        /** from == to 면 하루 전체가 범위 밖이라 늘 잡힌다 */
        const val ALWAYS = """{"signal":"UNUSUAL_TIME","from":"00:00","to":"00:00"}"""
    }
}
