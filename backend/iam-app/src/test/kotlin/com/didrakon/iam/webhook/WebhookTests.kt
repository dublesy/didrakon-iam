package com.didrakon.iam.webhook

import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.UserService
import com.didrakon.iam.authn.event.PasskeyChangedEvent
import com.didrakon.iam.governance.event.AccessReviewAction
import com.didrakon.iam.governance.event.AccessReviewCampaignEvent
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.risk.RiskPolicyChangedEvent
import com.sun.net.httpserver.HttpServer
import org.springframework.context.ApplicationEventPublisher
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.transaction.support.TransactionTemplate
import tools.jackson.databind.json.JsonMapper
import java.net.InetSocketAddress
import java.time.Duration
import java.time.Instant
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 받는 쪽: 요청 헤더·본문을 모으고 [statusCode] 로 답한다 */
class Receiver(private val statusCode: Int = 200) : AutoCloseable {
    class Request(val headers: Map<String, String>, val body: String)

    val received = LinkedBlockingQueue<Request>()
    private val server: HttpServer = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0).apply {
        createContext("/hook") { exchange ->
            received.add(
                Request(
                    exchange.requestHeaders.entries.associate { (k, v) -> k.lowercase() to v.first() },
                    exchange.requestBody.readAllBytes().toString(Charsets.UTF_8),
                ),
            )
            exchange.sendResponseHeaders(statusCode, -1)
            exchange.close()
        }
        start()
    }

    val url get() = "http://127.0.0.1:${server.address.port}/hook"

    override fun close() = server.stop(0)
}

/** webhook 구독·아웃박스·전달. 테스트마다 롤백하며, 전달 작업은 직접 부른다 (테스트 프로필은 스케줄러를 끈다) */
@AuthzTest
class WebhookTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val webhookService: WebhookService,
    private val dispatcher: WebhookDispatcher,
    private val userService: UserService,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val jdbc: JdbcTemplate,
    private val jsonMapper: JsonMapper,
    private val organizationService: OrganizationService,
    private val eventPublisher: ApplicationEventPublisher,
) {
    @Test
    fun `업무 변경은 받는 유형이 맞고 켜진 구독에만 전달을 쓴다`() {
        val matching = webhookService.create(WebhookSpec("사용자 상태", "http://127.0.0.1:9/a", listOf(WebhookEventTypes.USER_STATUS_CHANGED))).subscription
        val other = webhookService.create(WebhookSpec("역할", "http://127.0.0.1:9/b", listOf(WebhookEventTypes.ROLE_ASSIGNMENT_CHANGED))).subscription
        val off = webhookService.create(WebhookSpec("전체(꺼짐)", "http://127.0.0.1:9/c", listOf(WebhookEventTypes.ALL))).subscription
        webhookService.changeActive(off.subscriptionId, false)
        val userId = fixture.user()

        userService.changeStatus(userId, SubjectStatus.DISABLED)

        val delivery = webhookService.deliveries(matching.subscriptionId).single()
        assertEquals(WebhookEventTypes.USER_STATUS_CHANGED, delivery.eventType)
        assertEquals(DeliveryStatus.PENDING, delivery.status)
        val payload = jsonMapper.readTree(payloadOf(delivery.deliveryId))
        assertEquals(delivery.eventId, payload.path("id").asString())
        assertEquals(WebhookEventTypes.USER_STATUS_CHANGED, payload.path("type").asString())
        assertEquals(userId, payload.path("data").path("subjectId").asLong())
        assertEquals("DISABLED", payload.path("data").path("status").asString())
        assertTrue(webhookService.deliveries(other.subscriptionId).isEmpty())
        // 꺼진 구독은 자기 추가(config.changed)까지만 받고 이후 변경은 받지 않는다
        assertTrue(webhookService.deliveries(off.subscriptionId).none { it.eventType == WebhookEventTypes.USER_STATUS_CHANGED })
    }

    @Test
    fun `조직 이동·위험 정책·패스키·접근 재검토도 웹훅으로 나간다`() {
        val all = webhookService.create(WebhookSpec("전체", "http://127.0.0.1:9/a", listOf(WebhookEventTypes.ALL))).subscription
        val parent = fixture.org(OrgType.DEPARTMENT)
        val child = fixture.org(OrgType.TEAM)
        organizationService.move(child, parent)
        eventPublisher.publishEvent(RiskPolicyChangedEvent(7, "UPDATE", null, emptyMap()))
        eventPublisher.publishEvent(PasskeyChangedEvent(9, "cred-id", "내 노트북", added = true))
        eventPublisher.publishEvent(AccessReviewCampaignEvent(10, "점검", AccessReviewAction.ESCALATE, 3, null))

        val data = webhookService.deliveries(all.subscriptionId).associate { d ->
            val body = jsonMapper.readTree(payloadOf(d.deliveryId))
            (d.eventType + ":" + body.path("data").path("target").asString("")) to body.path("data")
        }
        assertEquals(child, data.getValue("organization.moved:").path("orgId").asLong())
        assertEquals(7, data.getValue("config.changed:RISK_POLICY").path("targetId").asLong())
        val credential = data.getValue("user.credential_changed:")
        assertEquals("ADDED", credential.path("change").asString())
        assertFalse(credential.toString().contains("cred-id") || credential.toString().contains("노트북"), "자격 증명 ID·이름은 보내지 않는다")
        assertEquals("ESCALATE", data.getValue("access_review.changed:").path("action").asString())
    }

    @Test
    fun `설정 변경은 대상과 행위만 보내고 전후 값은 보내지 않는다`() {
        val all = webhookService.create(WebhookSpec("전체", "http://127.0.0.1:9/a", listOf(WebhookEventTypes.ALL, WebhookEventTypes.CONFIG_CHANGED))).subscription
        assertEquals(listOf(WebhookEventTypes.ALL), all.eventTypes)
        val userId = fixture.user("이름바꿀사람")

        userService.update(userId, "새이름", null, null, null)

        val config = webhookService.deliveries(all.subscriptionId).first { it.eventType == WebhookEventTypes.CONFIG_CHANGED }
        val data = jsonMapper.readTree(payloadOf(config.deliveryId)).path("data")
        assertEquals("USER", data.path("target").asString())
        assertEquals(userId, data.path("targetId").asLong())
        assertEquals("UPDATE", data.path("action").asString())
        assertFalse(payloadOf(config.deliveryId).contains("새이름"))
    }

    @Test
    fun `전달 작업은 검증할 수 있는 서명과 함께 보내고 성공으로 남긴다`() {
        Receiver(200).use { receiver ->
            val created = webhookService.create(WebhookSpec("수신", receiver.url, listOf(WebhookEventTypes.USER_STATUS_CHANGED)))
            val delivery = webhookService.sendTest(created.subscription.subscriptionId)

            dispatcher.dispatchDue()

            val request = receiver.received.poll(5, TimeUnit.SECONDS) ?: throw AssertionError("전달이 오지 않았습니다")
            val timestamp = request.headers.getValue("x-didrakon-timestamp")
            assertEquals(WebhookSignature.sign(created.secret.toByteArray(), timestamp.toLong(), request.body), request.headers["x-didrakon-signature"])
            assertTrue(request.headers.getValue("x-didrakon-signature").startsWith("sha256="))
            assertEquals(hmacHex(created.secret, "$timestamp.${request.body}"), request.headers.getValue("x-didrakon-signature").removePrefix("sha256="))
            assertEquals(WebhookEventTypes.TEST, request.headers["x-didrakon-event"])
            assertEquals(delivery.deliveryId.toString(), request.headers["x-didrakon-delivery"])
            assertTrue(request.headers.getValue("content-type").startsWith("application/json"))
            assertEquals(payloadOf(delivery.deliveryId).let { jsonMapper.readTree(it) }, jsonMapper.readTree(request.body))

            val after = webhookService.deliveries(created.subscription.subscriptionId).single { it.deliveryId == delivery.deliveryId }
            assertEquals(DeliveryStatus.SUCCEEDED, after.status)
            assertEquals(1, after.attempts)
            assertEquals(200, after.lastStatusCode)
            assertTrue(after.deliveredAt != null)
        }
    }

    @Test
    fun `실패하면 미뤄 다시 보내고 여섯 번 실패하면 포기하며 다시 보내기로 되돌린다`() {
        Receiver(500).use { receiver ->
            val subscription = webhookService.create(WebhookSpec("실패", receiver.url, listOf(WebhookEventTypes.USER_STATUS_CHANGED))).subscription
            val deliveryId = webhookService.sendTest(subscription.subscriptionId).deliveryId
            val before = Instant.now()

            dispatcher.dispatchDue()

            val failed = delivery(subscription.subscriptionId, deliveryId)
            assertEquals(DeliveryStatus.FAILED, failed.status)
            assertEquals(1, failed.attempts)
            assertEquals(500, failed.lastStatusCode)
            assertEquals("HTTP 500", failed.lastError)
            assertTrue(failed.nextAttemptAt.isAfter(before.plus(Duration.ofSeconds(20))), "다음 시도는 30초 뒤")

            // 아직 차례가 아니면 보내지 않는다
            dispatcher.dispatchDue()
            assertEquals(1, delivery(subscription.subscriptionId, deliveryId).attempts)

            // 다섯 번 실패한 상태에서 차례가 되면 여섯 번째 실패로 포기한다
            jdbc.update("UPDATE webhook_delivery SET attempts = 5, next_attempt_at = NOW(6) - INTERVAL 1 SECOND WHERE delivery_id = ?", deliveryId)
            dispatcher.dispatchDue()
            val dead = delivery(subscription.subscriptionId, deliveryId)
            assertEquals(DeliveryStatus.DEAD, dead.status)
            assertEquals(WebhookDispatcher.MAX_ATTEMPTS, dead.attempts)
            dispatcher.dispatchDue()
            assertEquals(WebhookDispatcher.MAX_ATTEMPTS, delivery(subscription.subscriptionId, deliveryId).attempts, "포기한 전달은 다시 보내지 않는다")

            mockMvc.perform(post("/api/v1/webhook-deliveries/$deliveryId/redeliver").with(person(admin())))
                .andExpect(status().isOk)
                .andExpect(jsonPath("$.data.status").value("PENDING"))
                .andExpect(jsonPath("$.data.attempts").value(0))
            val reset = delivery(subscription.subscriptionId, deliveryId)
            assertFalse(reset.nextAttemptAt.isAfter(Instant.now()))
            assertNull(reset.lastError)
            assertEquals(2, receiver.received.size, "실제로 보낸 것은 첫 시도와 여섯 번째 시도뿐이다")
        }
    }

    @Test
    fun `구독마다 만든 순서대로 보내고 앞 전달이 끝나기 전에는 뒤 전달을 보내지 않는다`() {
        Receiver(200).use { receiver ->
            val subscription = webhookService.create(WebhookSpec("순서", receiver.url, listOf(WebhookEventTypes.USER_STATUS_CHANGED))).subscription
            val ids = (1..3).map { webhookService.sendTest(subscription.subscriptionId).deliveryId }

            dispatcher.dispatchDue()

            val order = (1..3).map { receiver.received.poll(5, TimeUnit.SECONDS)?.headers?.get("x-didrakon-delivery") }
            assertEquals(ids.map { it.toString() }, order, "한 번의 전달 작업에서 만든 순서대로 모두 보낸다")
        }
        Receiver(500).use { receiver ->
            val subscription = webhookService.create(WebhookSpec("막힘", receiver.url, listOf(WebhookEventTypes.USER_STATUS_CHANGED))).subscription
            val first = webhookService.sendTest(subscription.subscriptionId).deliveryId
            val second = webhookService.sendTest(subscription.subscriptionId).deliveryId

            dispatcher.dispatchDue()
            assertEquals(1, receiver.received.size, "앞 전달이 실패하면 뒤 전달은 기다린다")
            assertEquals(0, delivery(subscription.subscriptionId, second).attempts)

            // 앞 전달을 포기(DEAD)하면 뒤 전달이 같은 작업에서 나간다
            jdbc.update("UPDATE webhook_delivery SET attempts = 5, next_attempt_at = NOW(6) - INTERVAL 1 SECOND WHERE delivery_id = ?", first)
            dispatcher.dispatchDue()
            assertEquals(DeliveryStatus.DEAD, delivery(subscription.subscriptionId, first).status)
            assertEquals(1, delivery(subscription.subscriptionId, second).attempts)
        }
    }

    @Test
    fun `비밀값은 만들 때와 교체할 때 한 번만 주고 조회·감사 기록에는 없다`() {
        val admin = admin()
        val created = mockMvc.perform(
            post("/api/v1/webhooks").with(person(admin)).contentType(MediaType.APPLICATION_JSON)
                .content("""{"name":"ERP","url":"https://erp.example.com/hooks/iam","eventTypes":["user.status_changed","role_assignment.changed"]}"""),
        )
            .andExpect(status().isCreated)
            .andExpect(jsonPath("$.data.webhook.eventTypes.length()").value(2))
            .andReturn().response.contentAsString
        val body = jsonMapper.readTree(created).path("data")
        val secret = body.path("secret").asString()
        val id = body.path("webhook").path("webhookId").asLong()
        assertTrue(secret.startsWith("whsec_"))

        val list = mockMvc.perform(get("/api/v1/webhooks").with(person(admin))).andExpect(status().isOk).andReturn().response.contentAsString
        assertFalse(list.contains(secret))
        assertFalse(list.contains("secret", ignoreCase = true))

        val rotated = mockMvc.perform(post("/api/v1/webhooks/$id/rotate-secret").with(person(admin)))
            .andExpect(status().isOk).andReturn().response.contentAsString
        val newSecret = jsonMapper.readTree(rotated).path("data").path("secret").asString()
        assertNotEquals(secret, newSecret)
        assertTrue(newSecret.startsWith("whsec_"))
        val list2 = mockMvc.perform(get("/api/v1/webhooks").with(person(admin))).andReturn().response.contentAsString
        assertFalse(list2.contains(newSecret))

        val audit = jdbc.queryForList(
            "SELECT CONCAT(COALESCE(before_value, ''), COALESCE(after_value, '')) FROM audit_event WHERE resource_type = 'WEBHOOK' AND resource_id = ?",
            String::class.java, id.toString(),
        )
        assertTrue(audit.size >= 2, "추가·비밀값 교체가 감사에 남는다")
        assertTrue(audit.none { it.orEmpty().contains(secret) || it.orEmpty().contains(newSecret) })
    }

    @Test
    fun `주소와 이벤트 유형을 검사한다`() {
        val admin = admin()
        listOf(
            """{"name":"a","url":"ftp://example.com","eventTypes":["*"]}""",
            """{"name":"a","url":"/relative","eventTypes":["*"]}""",
            """{"name":"a","url":"https://example.com","eventTypes":["nope"]}""",
            """{"name":"a","url":"https://example.com","eventTypes":["webhook.test"]}""",
        ).forEach {
            mockMvc.perform(post("/api/v1/webhooks").with(person(admin)).contentType(MediaType.APPLICATION_JSON).content(it))
                .andExpect(status().isConflict)
        }
        mockMvc.perform(post("/api/v1/webhooks").with(person(admin)).contentType(MediaType.APPLICATION_JSON).content("""{"name":"a","url":"https://example.com","eventTypes":[]}"""))
            .andExpect(status().isBadRequest)
    }

    @Test
    fun `웹훅 권한이 없으면 거부된다`() {
        val user = fixture.user()
        mockMvc.perform(get("/api/v1/webhooks").with(person(user))).andExpect(status().isForbidden)
        mockMvc.perform(
            post("/api/v1/webhooks").with(person(user)).contentType(MediaType.APPLICATION_JSON)
                .content("""{"name":"a","url":"https://example.com","eventTypes":["*"]}"""),
        ).andExpect(status().isForbidden)
    }

    @Test
    fun `꺼진 웹훅에는 시험 이벤트를 넣지 않는다`() {
        val subscription = webhookService.create(WebhookSpec("꺼짐", "http://127.0.0.1:9/a", listOf(WebhookEventTypes.ALL))).subscription
        webhookService.changeActive(subscription.subscriptionId, false)
        mockMvc.perform(post("/api/v1/webhooks/${subscription.subscriptionId}/test").with(person(admin()))).andExpect(status().isConflict)
    }

    private fun delivery(subscriptionId: Long, deliveryId: Long) = webhookService.deliveries(subscriptionId).single { it.deliveryId == deliveryId }

    private fun payloadOf(deliveryId: Long): String =
        jdbc.queryForObject("SELECT payload FROM webhook_delivery WHERE delivery_id = ?", String::class.java, deliveryId) ?: throw AssertionError()

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun person(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }

    private fun hmacHex(secret: String, message: String): String {
        val mac = javax.crypto.Mac.getInstance("HmacSHA256").apply { init(javax.crypto.spec.SecretKeySpec(secret.toByteArray(), "HmacSHA256")) }
        return mac.doFinal(message.toByteArray()).joinToString("") { "%02x".format(it) }
    }
}

/** 아웃박스는 업무 트랜잭션과 함께 커밋·롤백된다. 실제 커밋이 필요해 롤백 테스트로 하지 않는다 */
@IntegrationTest
class WebhookOutboxTransactionTests @Autowired constructor(
    private val fixture: AuthzFixture,
    private val webhookService: WebhookService,
    private val userService: UserService,
    private val transactionTemplate: TransactionTemplate,
) {
    private var subscriptionId: Long? = null

    @BeforeEach
    fun subscribe() {
        subscriptionId = webhookService.create(WebhookSpec("롤백 확인", "http://127.0.0.1:9/a", listOf(WebhookEventTypes.USER_STATUS_CHANGED)))
            .subscription.subscriptionId
    }

    /** 다른 테스트의 변경이 이 구독에 쌓이지 않도록 끈다 */
    @AfterEach
    fun unsubscribe() {
        subscriptionId?.let { webhookService.changeActive(it, false) }
    }

    @Test
    fun `업무 변경이 롤백되면 전달도 남지 않고 커밋되면 남는다`() {
        val id = subscriptionId ?: throw AssertionError()
        val userId = fixture.user()

        transactionTemplate.executeWithoutResult {
            userService.changeStatus(userId, SubjectStatus.DISABLED)
            it.setRollbackOnly()
        }
        assertTrue(webhookService.deliveries(id).isEmpty())

        transactionTemplate.executeWithoutResult { userService.changeStatus(userId, SubjectStatus.DISABLED) }
        assertEquals(WebhookEventTypes.USER_STATUS_CHANGED, webhookService.deliveries(id).single().eventType)
    }
}
