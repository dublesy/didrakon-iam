package com.didrakon.iam.authn

import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.RegisteredClientResult
import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.json.JsonMapper
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 등록 후 SSO 클라이언트의 로그인 설정 수정과 비밀값 재발급이 실제 authorize·token 흐름에 바로 반영되는지 확인한다 */
@IntegrationTest
class ClientLifecycleTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val clientService: SsoClientService,
    private val ssoClientRepository: SsoClientRepository,
    private val registeredClientRepository: RegisteredClientRepository,
    private val accountService: LocalAccountService,
    private val assignmentService: RoleAssignmentService,
    private val roleRepository: RoleRepository,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
    private val jsonMapper: JsonMapper,
) {
    private val oldCallback = "https://old.example.com/callback"
    private val newCallback = "https://new.example.com/callback"

    @Test
    fun `redirect URI 를 고치면 client_id 는 그대로이고 authorize 는 새 주소만 받는다`() {
        val admin = admin()
        val client = webClient()
        val ssoClientId = client.ssoClient.requireId()
        val session = loggedInUser()
        authorize(client, oldCallback, session).andExpect(status().is3xxRedirection)

        updateClient(
            admin, ssoClientId,
            """{"clientName":"웹","redirectUris":["$newCallback"],"postLogoutRedirectUris":["https://new.example.com/"],"scopes":["orders.read"]}""",
        ).andExpect(status().isOk)

        authorize(client, oldCallback, session).andExpect(status().isBadRequest)
        val location = authorize(client, newCallback, session).andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl.orEmpty()
        assertTrue(location.startsWith(newCallback), location)

        val registered = registeredClientRepository.findByClientId(client.clientId) ?: throw AssertionError()
        assertEquals(client.ssoClient.registeredClientId, registered.id)
        assertEquals(setOf("openid", "profile", "orders.read"), registered.scopes)

        mockMvc.perform(get("/api/v1/clients").with(user(admin)))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[?(@.clientId == $ssoClientId)].redirectUris[0]").value(newCallback))
            .andExpect(jsonPath("$.data[?(@.clientId == $ssoClientId)].postLogoutRedirectUris[0]").value("https://new.example.com/"))
            .andExpect(jsonPath("$.data[?(@.clientId == $ssoClientId)].confidential").value(true))

        val audit = jdbc.queryForList(
            "SELECT action FROM audit_event WHERE resource_type = 'CLIENT' AND resource_id = ? ORDER BY event_id", String::class.java, ssoClientId.toString(),
        )
        assertEquals(listOf("UPDATE"), audit)
    }

    @Test
    fun `로그인 설정이 잘못되면 거부하고 관리 콘솔 클라이언트의 로그인 설정은 바꿀 수 없다`() {
        val admin = admin()
        val client = webClient()
        val id = client.ssoClient.requireId()

        updateClient(admin, id, """{"clientName":"웹","redirectUris":[]}""").andExpect(status().isConflict)
        updateClient(admin, id, """{"clientName":"웹","redirectUris":["/relative/callback"]}""").andExpect(status().isConflict)
        updateClient(admin, id, """{"clientName":"웹","redirectUris":["https://app.example.com/cb#frag"]}""").andExpect(status().isConflict)
        updateClient(admin, id, """{"clientName":"웹","scopes":["bad\"scope"]}""").andExpect(status().isConflict)
        assertEquals(setOf(oldCallback), registeredClientRepository.findByClientId(client.clientId)?.redirectUris)

        val batch = clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH))
        updateClient(admin, batch.ssoClient.requireId(), """{"clientName":"배치","redirectUris":["$newCallback"]}""").andExpect(status().isConflict)

        val console = ssoClientRepository.findByClientCode("iam-admin") ?: throw AssertionError()
        val consoleUris = registeredClientRepository.findById(console.registeredClientId)?.redirectUris ?: throw AssertionError()
        updateClient(admin, console.requireId(), """{"clientName":"${console.clientName}","redirectUris":["https://evil.example.com/callback"]}""")
            .andExpect(status().isConflict)
        // 같은 값을 그대로 보내거나 생략하면 다른 항목은 고칠 수 있다
        updateClient(
            admin, console.requireId(),
            """{"clientName":"${console.clientName}","redirectUris":${jsonMapper.writeValueAsString(consoleUris)}}""",
        ).andExpect(status().isOk)
        assertEquals(consoleUris, registeredClientRepository.findById(console.registeredClientId)?.redirectUris)
    }

    @Test
    fun `비밀값을 재발급하면 이전 비밀값은 바로 거부되고 새 비밀값으로 토큰을 받는다`() {
        val admin = admin()
        val client = clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH))
        val oldSecret = client.clientSecret ?: throw AssertionError()
        val issued = tokenRequest(client.clientId, oldSecret).andExpect(status().isOk).andReturn().response.contentAsString
        val oldToken = jsonMapper.readTree(issued)["access_token"].stringValue()

        val body = mockMvc.perform(post("/api/v1/clients/${client.ssoClient.requireId()}/rotate-secret").with(user(admin)))
            .andExpect(status().isOk).andReturn().response.contentAsString
        val newSecret = jsonMapper.readTree(body)["data"]["clientSecret"].stringValue()

        tokenRequest(client.clientId, oldSecret).andExpect(status().isUnauthorized)
        tokenRequest(client.clientId, newSecret).andExpect(status().isOk)
        assertEquals(client.clientId, registeredClientRepository.findByClientId(client.clientId)?.clientId)
        // 이미 받은 토큰은 만료될 때까지 그대로다
        val active = mockMvc.perform(post("/oauth2/introspect").with(httpBasic(client.clientId, newSecret)).param("token", oldToken))
            .andExpect(status().isOk).andReturn().response.contentAsString
        assertTrue(jsonMapper.readTree(active)["active"].booleanValue())

        val audit = jdbc.queryForList(
            "SELECT after_value FROM audit_event WHERE resource_type = 'CLIENT' AND resource_id = ? AND action = 'ROTATE_SECRET'",
            String::class.java, client.ssoClient.requireId().toString(),
        )
        assertEquals(1, audit.size)
        assertFalse(audit.single().orEmpty().contains(newSecret))
    }

    @Test
    fun `비밀값 없는 public client 는 재발급할 수 없다`() {
        val admin = admin()
        val client = clientService.register(
            ClientRegistration("spa-${System.nanoTime()}", "SPA", ClientType.WEB, redirectUris = setOf(oldCallback), confidential = false),
        )
        mockMvc.perform(post("/api/v1/clients/${client.ssoClient.requireId()}/rotate-secret").with(user(admin)))
            .andExpect(status().isConflict)
    }

    private fun webClient(): RegisteredClientResult =
        clientService.register(ClientRegistration("web-${System.nanoTime()}", "웹", ClientType.WEB, redirectUris = setOf(oldCallback)))

    private fun updateClient(admin: Long, ssoClientId: Long, body: String) =
        mockMvc.perform(put("/api/v1/clients/$ssoClientId").with(user(admin)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun authorize(client: RegisteredClientResult, redirectUri: String, session: MockHttpSession) =
        mockMvc.perform(
            get(
                UriComponentsBuilder.fromPath("/oauth2/authorize")
                    .queryParam("response_type", "code").queryParam("client_id", client.clientId)
                    .queryParam("redirect_uri", redirectUri).queryParam("scope", "openid").queryParam("state", "state-1")
                    .encode().build().toUriString(),
            ).session(session),
        )

    private fun tokenRequest(clientId: String, secret: String) =
        mockMvc.perform(post("/oauth2/token").with(httpBasic(clientId, secret)).param("grant_type", "client_credentials"))

    private fun loggedInUser(): MockHttpSession {
        val userId = fixture.user()
        val loginId = "user${System.nanoTime()}"
        accountService.createAccount(userId, loginId, PASSWORD)
        val session = MockHttpSession()
        mockMvc.perform(post("/login").param("username", loginId).param("password", PASSWORD).session(session).with(csrf()))
            .andExpect(status().is3xxRedirection)
        return session
    }

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }

    companion object {
        private const val PASSWORD = "correct-horse-battery"
    }
}
