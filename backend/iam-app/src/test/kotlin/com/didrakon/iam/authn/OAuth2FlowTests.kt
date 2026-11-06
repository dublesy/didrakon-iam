package com.didrakon.iam.authn

import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authn.client.ClientRegistration
import com.didrakon.iam.authn.config.AuthnProperties
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import java.net.URI
import com.didrakon.iam.authn.client.ClientType
import com.didrakon.iam.authn.client.RegisteredClientResult
import com.didrakon.iam.authn.client.SsoClientService
import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.common.crypto.sha256Hex
import com.didrakon.iam.common.error.BusinessRuleException
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.http.MediaType
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.util.UriComponentsBuilder
import tools.jackson.databind.JsonNode
import tools.jackson.databind.json.JsonMapper
import java.time.Instant
import java.util.Base64
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** 실제 OAuth2·OIDC 흐름에서 토큰이 hash 로만 저장되고, 폐기·검사·회전이 그대로 동작하는지 확인한다 */
@IntegrationTest
class OAuth2FlowTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val clientService: SsoClientService,
    private val accountService: LocalAccountService,
    private val sessionService: LoginSessionService,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
    private val jsonMapper: JsonMapper,
    private val mfaService: MfaService,
    private val userService: UserService,
    private val apiKeyService: ApiKeyService,
    private val assignmentService: RoleAssignmentService,
    private val jwtDecoder: org.springframework.security.oauth2.jwt.JwtDecoder,
    private val rsaKey: com.nimbusds.jose.jwk.RSAKey,
    private val mfaMethodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val authnProperties: AuthnProperties,
) {
    private val callback = "https://app.example.com/callback"
    private val afterLogout = "https://app.example.com/"
    private val password = "correct-horse-battery"

    @Test
    fun `authorization code 흐름의 code·토큰은 hash 로만 저장되고 sub 는 subject ID 다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()

        val code = authorize(client, session)
        val tokens = exchangeCode(client, code)

        val stored = storedValues(client)
        assertEquals(sha256Hex(code), stored["authorization_code_value"])
        assertEquals(sha256Hex(tokens["access_token"].stringValue()), stored["access_token_value"])
        assertEquals(sha256Hex(tokens["refresh_token"].stringValue()), stored["refresh_token_value"])
        assertEquals(sha256Hex(tokens["id_token"].stringValue()), stored["oidc_id_token_value"])

        val claims = payload(tokens["access_token"].stringValue())
        assertEquals(userId.toString(), claims["sub"].stringValue())
        assertEquals(listOf("pwd"), claims["amr"].values().map { it.stringValue() })
    }

    @Test
    fun `사용자 토큰에는 사번·소속·역할 claim 이 들어가고 refresh 해도 유지된다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val org = fixture.org(OrgType.TEAM).also { fixture.join(userId, it) }
        val role = fixture.role().also { assignmentService.assignDirect(userId, it.requireId()) }

        val tokens = exchangeCode(client, authorize(client, session))
        val claims = payload(tokens["access_token"].stringValue())
        assertEquals(org.toString(), claims["primary_org_id"].stringValue())
        assertEquals(listOf(role.roleCode), strings(claims["roles"]))
        assertTrue(claims["emp_no"].stringValue().isNotBlank())
        assertEquals(listOf(role.roleCode), strings(payload(tokens["id_token"].stringValue())["roles"]))

        val refreshed = json(tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to tokens["refresh_token"].stringValue()).andExpect(status().isOk))
        assertEquals(org.toString(), payload(refreshed["access_token"].stringValue())["primary_org_id"].stringValue())
    }

    @Test
    fun `시스템 간 토큰(client credentials)에는 사용자 claim 을 넣지 않는다`() {
        val client = clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH))
        val token = json(tokenRequest(client, "grant_type" to "client_credentials").andExpect(status().isOk))["access_token"].stringValue()
        assertFalse(payload(token).has("roles"))
    }

    @Test
    fun `같은 code 는 두 번 쓸 수 없다`() {
        val client = webClient()
        val code = authorize(client, loggedInUser().second)
        exchangeCode(client, code)

        tokenRequest(client, "grant_type" to "authorization_code", "code" to code, "redirect_uri" to callback)
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `refresh token 은 쓸 때마다 바뀌고 이전 refresh token 은 거부된다`() {
        val client = webClient()
        val first = exchangeCode(client, authorize(client, loggedInUser().second))["refresh_token"].stringValue()

        val second = json(tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to first).andExpect(status().isOk))
        assertNotEquals(first, second["refresh_token"].stringValue())

        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to first).andExpect(status().isBadRequest)
    }

    @Test
    fun `관리자가 로그인 세션을 끊으면 그 세션에서 받은 refresh token 도 쓸 수 없다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val refresh = exchangeCode(client, authorize(client, session))["refresh_token"].stringValue()
        // 다른 세션에서 받은 토큰은 남아야 한다
        val otherSession = MockHttpSession().also { other ->
            mockMvc.perform(post("/login").param("username", loginIdOf(userId)).param("password", password).session(other).with(csrf()))
        }
        val otherRefresh = exchangeCode(client, authorize(client, otherSession))["refresh_token"].stringValue()

        sessionService.revoke(sessionService.activeSessions(userId).minBy { it.requireId() }.requireId())

        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to refresh).andExpect(status().isBadRequest)
        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to otherRefresh).andExpect(status().isOk)
    }

    @Test
    fun `로그인 세션이 만료되면 그 세션에서 받은 refresh token 으로 새 토큰을 받을 수 없다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val refresh = exchangeCode(client, authorize(client, session))["refresh_token"].stringValue()
        val rotated = jsonMapper.readTree(
            tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to refresh).andExpect(status().isOk).andReturn().response.contentAsString,
        )["refresh_token"].stringValue()

        // 8시간 절대 만료가 지난 것처럼 만든다 (만료 시각을 로그인 시각으로)
        jdbc.update("UPDATE login_session SET expire_at = login_at WHERE subject_id = ?", userId)

        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to rotated).andExpect(status().isBadRequest)
    }

    @Test
    fun `Supabase 호환을 켠 클라이언트의 토큰에만 role = authenticated 가 들어간다`() {
        val (_, session) = loggedInUser()
        val supabase = webClient(supabaseRoleClaim = true)
        val tokens = exchangeCode(supabase, authorize(supabase, session))
        assertEquals("authenticated", payload(tokens["access_token"].stringValue())["role"].stringValue())
        assertEquals("authenticated", payload(tokens["id_token"].stringValue())["role"].stringValue())

        val plain = webClient()
        val plainTokens = exchangeCode(plain, authorize(plain, session))
        assertTrue(payload(plainTokens["access_token"].stringValue())["role"] == null, "끈 클라이언트에는 role 이 없다")
    }

    @Test
    fun `로그인을 마친 사람이 로그인 화면을 직접 열면 홈으로 보내고, 안내 문구가 있거나 로그인 전이면 폼을 보인다`() {
        val (_, session) = loggedInUser()
        mockMvc.perform(get("/login").session(session)).andExpect(status().is3xxRedirection).andExpect(redirectedUrl("/"))
        mockMvc.perform(get("/login").param("logout", "").session(session)).andExpect(status().isOk)
        mockMvc.perform(get("/login")).andExpect(status().isOk)
    }

    @Test
    fun `discovery 문서는 back-channel 로그아웃과 sid 지원을 알린다`() {
        val config = json(mockMvc.perform(get("/.well-known/openid-configuration")).andExpect(status().isOk))
        assertTrue(config["backchannel_logout_supported"].booleanValue())
        assertTrue(config["backchannel_logout_session_supported"].booleanValue())
    }

    @Test
    fun `세션을 끊으면 수신 주소를 등록한 연동 시스템에 서명한 로그아웃 토큰을 보낸다`() {
        val received = java.util.concurrent.LinkedBlockingQueue<String>()
        val server = com.sun.net.httpserver.HttpServer.create(java.net.InetSocketAddress("127.0.0.1", 0), 0).apply {
            createContext("/bcl") { exchange ->
                // Next.js 처럼 h2c 업그레이드 요청을 거부하는 받는 쪽을 흉내 낸다 (IAM 은 HTTP/1.1 로 보내야 한다)
                if (exchange.requestHeaders.containsKey("Upgrade")) {
                    exchange.sendResponseHeaders(400, -1)
                } else {
                    received.add(exchange.requestBody.readAllBytes().toString(Charsets.UTF_8))
                    exchange.sendResponseHeaders(200, -1)
                }
                exchange.close()
            }
            start()
        }
        try {
            val client = clientService.register(
                ClientRegistration(
                    "bcl-${System.nanoTime()}", "웹", ClientType.WEB, redirectUris = setOf(callback),
                    backchannelLogoutUri = "http://127.0.0.1:${server.address.port}/bcl",
                ),
            )
            val (userId, session) = loggedInUser()
            val idToken = exchangeCode(client, authorize(client, session))["id_token"].stringValue()
            val sid = payload(idToken)["sid"].stringValue()
            assertTrue(sid.isNotBlank(), "ID 토큰에 로그인 세션의 sid 가 있다")

            sessionService.revoke(sessionService.activeSessions(userId).single().requireId())

            val body = received.poll(5, java.util.concurrent.TimeUnit.SECONDS) ?: throw AssertionError("로그아웃 토큰이 오지 않았습니다")
            val token = java.net.URLDecoder.decode(body.removePrefix("logout_token="), Charsets.UTF_8)
            val jwt = com.nimbusds.jwt.SignedJWT.parse(token)
            assertTrue(jwt.verify(com.nimbusds.jose.crypto.RSASSAVerifier(rsaKey.toRSAPublicKey())), "IAM 서명 키로 검증되어야 한다")
            assertEquals("logout+jwt", jwt.header.type.type)
            assertEquals(userId.toString(), jwt.jwtClaimsSet.subject)
            assertEquals(listOf(client.clientId), jwt.jwtClaimsSet.audience)
            assertTrue(jwt.jwtClaimsSet.getJSONObjectClaim("events").containsKey("http://schemas.openid.net/event/backchannel-logout"))
            assertEquals(sid, jwt.jwtClaimsSet.getStringClaim("sid"), "세션 하나만 끝났으므로 ID 토큰과 같은 sid 를 넣는다")
            // 로그아웃 토큰은 API 접근 토큰으로 쓸 수 없다 (typ 이 달라 거부)
            assertThrows<org.springframework.security.oauth2.jwt.JwtException> { jwtDecoder.decode(token) }
        } finally {
            server.stop(0)
        }
    }

    @Test
    fun `사용자를 사용 중지하면 세션·refresh token·API 키가 모두 회수된다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val refresh = exchangeCode(client, authorize(client, session))["refresh_token"].stringValue()
        val apiKey = apiKeyService.issue(userId, "배치").rawKey

        userService.changeStatus(userId, SubjectStatus.DISABLED)

        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to refresh).andExpect(status().isBadRequest)
        assertEquals(emptyList(), sessionService.activeSessions(userId))
        assertEquals(null, apiKeyService.authenticate(apiKey))
    }

    @Test
    fun `토큰 검사(introspection)와 폐기가 hash 저장에서도 동작한다`() {
        val client = webClient()
        val tokens = exchangeCode(client, authorize(client, loggedInUser().second))
        val refresh = tokens["refresh_token"].stringValue()

        assertTrue(introspect(client, tokens["access_token"].stringValue())["active"].booleanValue())
        assertTrue(introspect(client, refresh)["active"].booleanValue())

        mockMvc.perform(post("/oauth2/revoke").with(httpBasic(client.clientId, client.secret())).param("token", refresh))
            .andExpect(status().isOk)

        assertFalse(introspect(client, refresh)["active"].booleanValue())
    }

    @Test
    fun `client credentials 로 받은 토큰도 hash 로만 저장된다`() {
        val client = clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH))

        val token = json(tokenRequest(client, "grant_type" to "client_credentials").andExpect(status().isOk))["access_token"].stringValue()

        assertEquals(sha256Hex(token), storedValues(client)["access_token_value"])
    }

    @Test
    fun `로그인 전 authorize 로 들어와 비밀번호와 MFA 를 마치면 다른 탭·정적 자원 요청과 관계없이 authorize 로 돌아간다`() {
        val client = webClient()
        val userId = fixture.user()
        val loginId = "user${System.nanoTime()}"
        accountService.createAccount(userId, loginId, password)
        val enrollment = mfaService.enrollTotp(userId, loginId)
        val reference = mfaMethodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        val secret = secretStore.load(reference)
        mfaService.confirmTotp(userId, enrollment.methodId, Totp.code(secret, Instant.now()))
        val session = MockHttpSession()

        authorizeRequest(client, session, MediaType.TEXT_HTML).andExpect(status().is3xxRedirection)
        // 같은 브라우저의 다른 탭이 로그인 전에 IAM 의 다른 주소를 연다
        mockMvc.perform(get("/").session(session).accept(MediaType.TEXT_HTML)).andExpect(status().is3xxRedirection)
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(session).with(csrf()))
            .andExpect(redirectedUrl("/login/mfa"))
        mockMvc.perform(get("/login/mfa").session(session).accept(MediaType.TEXT_HTML)).andExpect(status().isOk)
        mockMvc.perform(get("/iam-login/login.css").session(session)).andExpect(status().isOk)
        mockMvc.perform(get("/favicon.ico").session(session).accept(MediaType.ALL))
        val afterMfa = mockMvc.perform(
            post("/login/mfa").param("code", Totp.code(secret, Instant.now().plusSeconds(30))).session(session).with(csrf()),
        ).andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl ?: throw AssertionError("redirect 없음")

        assertTrue("/oauth2/authorize" in afterMfa, afterMfa)
    }

    @Test
    fun `MFA 필수 클라이언트는 MFA 를 등록하지 않은 사용자의 로그인을 거부한다`() {
        val client = webClient(requireMfa = true)

        authorizeRequest(client, loggedInUser().second).andExpect(status().isForbidden)
    }

    @Test
    fun `MFA 필수 클라이언트 검사는 인코딩한 authorize 경로로도 건너뛸 수 없다`() {
        val client = webClient(requireMfa = true)
        val session = loggedInUser().second
        val query = UriComponentsBuilder.newInstance()
            .queryParam("response_type", "code").queryParam("client_id", client.clientId)
            .queryParam("redirect_uri", callback).queryParam("scope", "openid").queryParam("state", "state-1")
            .encode().build().query

        for (path in listOf("/oauth2/%61uthorize", "/oauth2/authoriz%65", "/%6fauth2/authorize")) {
            mockMvc.perform(get(URI.create("$path?$query")).session(session).accept(MediaType.ALL))
                .andExpect(status().isForbidden)
        }
    }

    @Test
    fun `관리 API 는 다른 연동 시스템이 받은 접근 토큰·ID 토큰을 받지 않는다`() {
        val client = webClient()
        val tokens = exchangeCode(client, authorize(client, loggedInUser().second))

        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer ${tokens["access_token"].stringValue()}"))
            .andExpect(status().isUnauthorized)
        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer ${tokens["id_token"].stringValue()}"))
            .andExpect(status().isUnauthorized)
    }

    @Test
    fun `관리 API 는 관리 콘솔 사용자 토큰과 시스템 간 토큰은 받는다`() {
        val userId = fixture.user()
        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer ${signed(userId.toString(), "iam-admin")}"))
            .andExpect(status().isOk)
        // 관리 콘솔의 ID 토큰(azp 있음)은 받지 않는다
        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer ${signed(userId.toString(), "iam-admin", azp = "iam-admin")}"))
            .andExpect(status().isUnauthorized)

        // client credentials 토큰(sub = aud = client_id)은 인증을 통과한다. /me 는 사람이 아니라서 403
        val batch = clientService.register(ClientRegistration("batch-${System.nanoTime()}", "배치", ClientType.BATCH))
        val systemToken = json(tokenRequest(batch, "grant_type" to "client_credentials").andExpect(status().isOk))["access_token"].stringValue()
        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer $systemToken")).andExpect(status().isForbidden)
    }

    @Test
    fun `숫자로만 된 클라이언트 코드는 등록할 수 없고, 시스템 간 토큰은 같은 번호의 사용자로 취급하지 않는다`() {
        val userId = fixture.user()
        assertThrows<BusinessRuleException> {
            clientService.register(ClientRegistration(userId.toString(), "숫자 코드", ClientType.BATCH))
        }
        // sub = aud 인 토큰(client credentials 모양)은 sub 가 숫자여도 사람이 아니다
        mockMvc.perform(get("/api/v1/me").header("Authorization", "Bearer ${signed(userId.toString(), userId.toString())}"))
            .andExpect(status().isForbidden)
    }

    @Test
    fun `비밀번호를 바꾸면 그 사람의 로그인 세션과 refresh token 이 모두 끝난다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val refresh = exchangeCode(client, authorize(client, session))["refresh_token"].stringValue()
        val identityId = accountService.findLocalIdentity(userId)?.requireId() ?: throw AssertionError()

        accountService.changePassword(identityId, "another-secret-9")

        assertEquals(emptyList(), sessionService.activeSessions(userId))
        tokenRequest(client, "grant_type" to "refresh_token", "refresh_token" to refresh).andExpect(status().isBadRequest)
    }

    @Test
    fun `RP 로그아웃(connect logout)은 로그인 세션을 닫고 등록된 주소로 돌려보낸다`() {
        val client = webClient()
        val (userId, session) = loggedInUser()
        val idToken = exchangeCode(client, authorize(client, session))["id_token"].stringValue()

        mockMvc.perform(
            get(
                UriComponentsBuilder.fromPath("/connect/logout")
                    .queryParam("id_token_hint", idToken).queryParam("post_logout_redirect_uri", afterLogout)
                    .encode().build().toUriString(),
            ).session(session),
        ).andExpect(status().is3xxRedirection).andExpect(redirectedUrl(afterLogout))

        assertEquals(emptyList(), sessionService.activeSessions(userId))
    }

    private fun webClient(requireMfa: Boolean = false, supabaseRoleClaim: Boolean = false): RegisteredClientResult =
        clientService.register(
            ClientRegistration(
                "web-${System.nanoTime()}", "웹", ClientType.WEB,
                redirectUris = setOf(callback), postLogoutRedirectUris = setOf(afterLogout), requireMfa = requireMfa,
                supabaseRoleClaim = supabaseRoleClaim,
            ),
        )

    private val loginIds = mutableMapOf<Long, String>()

    private fun loginIdOf(userId: Long) = loginIds[userId] ?: throw AssertionError("로그인 ID 없음: $userId")

    private fun loggedInUser(): Pair<Long, MockHttpSession> {
        val userId = fixture.user()
        val loginId = "user${System.nanoTime()}".also { loginIds[userId] = it }
        accountService.createAccount(userId, loginId, password)
        val session = MockHttpSession()
        mockMvc.perform(post("/login").param("username", loginId).param("password", password).session(session).with(csrf()))
            .andExpect(status().is3xxRedirection)
        return userId to session
    }

    private fun authorizeRequest(client: RegisteredClientResult, session: MockHttpSession, accept: MediaType = MediaType.ALL) =
        // SAS 는 authorize 파라미터를 쿼리 문자열에서 읽는다
        mockMvc.perform(
            get(
                UriComponentsBuilder.fromPath("/oauth2/authorize")
                    .queryParam("response_type", "code").queryParam("client_id", client.clientId)
                    .queryParam("redirect_uri", callback).queryParam("scope", "openid").queryParam("state", "state-1")
                    .encode().build().toUriString(),
            ).session(session).accept(accept),
        )

    private fun authorize(client: RegisteredClientResult, session: MockHttpSession): String {
        val location = authorizeRequest(client, session).andExpect(status().is3xxRedirection).andReturn().response.redirectedUrl
            ?: throw AssertionError("redirect 가 없습니다")
        assertTrue(location.startsWith(callback), location)
        return UriComponentsBuilder.fromUriString(location).build().queryParams.getFirst("code") ?: throw AssertionError("code 가 없습니다")
    }

    private fun exchangeCode(client: RegisteredClientResult, code: String): JsonNode =
        json(tokenRequest(client, "grant_type" to "authorization_code", "code" to code, "redirect_uri" to callback).andExpect(status().isOk))

    private fun tokenRequest(client: RegisteredClientResult, vararg params: Pair<String, String>) =
        mockMvc.perform(
            post("/oauth2/token").with(httpBasic(client.clientId, client.secret())).apply { params.forEach { (k, v) -> param(k, v) } },
        )

    private fun introspect(client: RegisteredClientResult, token: String): JsonNode =
        json(mockMvc.perform(post("/oauth2/introspect").with(httpBasic(client.clientId, client.secret())).param("token", token)).andExpect(status().isOk))

    private fun storedValues(client: RegisteredClientResult): Map<String, Any?> =
        jdbc.queryForMap(
            """
            SELECT a.authorization_code_value, a.access_token_value, a.refresh_token_value, a.oidc_id_token_value
            FROM oauth2_authorization a JOIN oauth2_registered_client c ON c.id = a.registered_client_id
            WHERE c.client_id = ?
            """,
            client.clientId,
        )

    private fun json(result: org.springframework.test.web.servlet.ResultActions): JsonNode =
        jsonMapper.readTree(result.andReturn().response.contentAsString)

    private fun RegisteredClientResult.secret(): String = clientSecret ?: throw AssertionError("비밀값 없는 클라이언트")

    private fun strings(array: JsonNode): List<String> = (0 until array.size()).map { array.get(it).stringValue() }

    /** IAM 서명 키로 서명한 접근 토큰 모양의 JWT */
    private fun signed(subject: String, audience: String, azp: String? = null): String {
        val now = Instant.now()
        val claims = JwtClaimsSet.builder().issuer(authnProperties.issuer).subject(subject).audience(listOf(audience))
            .issuedAt(now).expiresAt(now.plusSeconds(300)).claim("amr", listOf("pwd", "otp"))
            .apply { if (azp != null) claim("azp", azp) }.build()
        val encoder = NimbusJwtEncoder(ImmutableJWKSet(JWKSet(rsaKey)))
        return encoder.encode(JwtEncoderParameters.from(JwsHeader.with(SignatureAlgorithm.RS256).build(), claims)).tokenValue
    }

    private fun payload(jwt: String): JsonNode = jsonMapper.readTree(Base64.getUrlDecoder().decode(jwt.split(".")[1]))
}
