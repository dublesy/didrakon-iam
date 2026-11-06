package com.didrakon.iam.risk

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.decision.AuthorizationRequest
import com.didrakon.iam.authz.decision.PolicyDecisionPoint
import com.didrakon.iam.authz.role.PermissionAction
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.governance.request.AccessRequestService
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl
import java.net.InetAddress
import java.time.Instant
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** 기본 정책(V9)은 테스트마다 끄고, 결과가 시각에 좌우되지 않는 정책만 넣어 확인한다. 테스트마다 롤백된다 */
@AuthzTest
class RiskTests @Autowired constructor(
    private val riskEngine: RiskEngine,
    private val policyRepository: RiskPolicyRepository,
    private val assessmentRepository: RiskAssessmentRepository,
    private val signalRepository: RiskSignalRepository,
    private val pdp: PolicyDecisionPoint,
    private val assignmentService: RoleAssignmentService,
    private val accessRequestService: AccessRequestService,
    private val accountService: LocalAccountService,
    private val mfaService: MfaService,
    private val mfaMethodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val jdbc: JdbcTemplate,
) {
    @BeforeEach
    fun disableSeedPolicies() {
        jdbc.update("UPDATE risk_policy SET is_active = FALSE")
    }

    @Test
    fun `잡힌 신호의 점수를 더하고 가장 강한 조치를 택하며 신호와 평가를 남긴다`() {
        policy(RiskType.LOGIN, """{"signal":"NEW_DEVICE"}""", 20, RiskAction.CHALLENGE)
        policy(RiskType.LOGIN, """{"signal":"FAILED_LOGIN_BURST","threshold":3}""", 30, RiskAction.APPROVAL)
        policy(RiskType.LOGIN, """{"signal":"FAILED_LOGIN_BURST","threshold":10}""", 40, RiskAction.DENY)
        val userId = fixture.user()

        val outcome = riskEngine.assess(RiskContext(userId, RiskType.LOGIN, knownDevice = false, consecutiveFailures = 4))

        assertEquals(50, outcome.score)
        assertEquals(RiskLevel.HIGH, outcome.level)
        assertEquals(RiskAction.APPROVAL, outcome.decision)
        assertEquals(setOf(RiskSignalType.NEW_DEVICE, RiskSignalType.FAILED_LOGIN_BURST), signalRepository.findBySubjectIdOrderByDetectedAtDesc(userId).map { it.signalType }.toSet())
        assertEquals(50, assessmentRepository.findBySubjectIdOrderByAssessedAtDesc(userId).single().riskScore)
    }

    @Test
    fun `점수 합이 80 이상이면 정책 조치와 관계없이 DENY 다`() {
        policy(RiskType.LOGIN, """{"signal":"NEW_DEVICE"}""", 50, RiskAction.ALLOW)
        policy(RiskType.LOGIN, ALWAYS, 40, RiskAction.ALLOW)

        val outcome = riskEngine.evaluate(RiskContext(fixture.user(), RiskType.LOGIN, knownDevice = false))

        assertEquals(90, outcome.score)
        assertEquals(RiskLevel.CRITICAL, outcome.level)
        assertEquals(RiskAction.DENY, outcome.decision)
    }

    @Test
    fun `모르는 사실로는 신호를 만들지 않고 기록도 남기지 않는다`() {
        policy(RiskType.LOGIN, """{"signal":"NEW_DEVICE"}""", 20, RiskAction.CHALLENGE)
        policy(RiskType.LOGIN, """{"signal":"FOREIGN_IP"}""", 50, RiskAction.CHALLENGE)
        policy(RiskType.LOGIN, """{"signal":"FAILED_LOGIN_BURST"}""", 30, RiskAction.CHALLENGE)
        val userId = fixture.user()

        // 기기 이력·실패 횟수를 모르고, 이 IP 의 국가를 모른다 (테스트 설정의 CIDR 대역 밖)
        val outcome = riskEngine.assess(RiskContext(userId, RiskType.LOGIN, ipAddress = "198.51.100.10"))

        assertEquals(0, outcome.score)
        assertEquals(RiskAction.ALLOW, outcome.decision)
        assertTrue(assessmentRepository.findBySubjectIdOrderByAssessedAtDesc(userId).isEmpty())
    }

    @Test
    fun `대량 조회 정책은 정책이 정한 구간의 판정 횟수를 묻는다`() {
        policy(RiskType.DATA_ACCESS, """{"signal":"MASS_ACCESS","threshold":5,"windowSeconds":30}""", 60, RiskAction.CHALLENGE)
        val asked = mutableListOf<Instant>()
        val before = Instant.now()

        val outcome = riskEngine.evaluate(RiskContext(fixture.user(), RiskType.DATA_ACCESS, accessCountSince = { asked += it; 7 }))

        assertEquals(60, outcome.score)
        assertTrue(asked.single().isBefore(before.minusSeconds(29)))
    }

    @Test
    fun `권한 판정은 위험 점수를 판정 로그와 ABAC CONTEXT 에 남긴다`() {
        policy(RiskType.DATA_ACCESS, """{"signal":"MASS_ACCESS","threshold":1,"windowSeconds":60}""", 60, RiskAction.CHALLENGE)
        val userId = fixture.user()
        val resource = fixture.resource()
        assignmentService.assignDirect(userId, fixture.roleAllowing(resource.requireId()).requireId())

        val first = pdp.decide(AuthorizationRequest(userId, resource.requireId(), PermissionAction.READ, traceId = "risk-1"))
        val second = pdp.decide(AuthorizationRequest(userId, resource.requireId(), PermissionAction.READ, traceId = "risk-2"))

        assertEquals(0, first.riskScore)
        assertEquals(60, second.riskScore)
        assertEquals(60, jdbc.queryForObject("SELECT risk_score FROM authorization_log WHERE trace_id = 'risk-2'", Int::class.java))
    }

    @Test
    fun `위험 평가가 DENY 면 비밀번호가 맞아도 로그인되지 않는다`() {
        policy(RiskType.LOGIN, ALWAYS, 90, RiskAction.ALLOW)
        val userId = fixture.user()
        val loginId = "risk${System.nanoTime()}"
        accountService.createAccount(userId, loginId, PASSWORD)

        mockMvc.perform(post("/login").param("username", loginId).param("password", PASSWORD).with(csrf()))
            .andExpect(redirectedUrl("/login?risk"))

        val failures = jdbc.queryForObject(
            "SELECT COUNT(*) FROM authentication_event WHERE subject_id = ? AND result = 'FAILURE' AND failure_reason LIKE 'RISK_DENIED%'",
            Int::class.java, userId,
        )
        assertEquals(1, failures)
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM login_session WHERE subject_id = ?", Int::class.java, userId))
    }

    @Test
    fun `위험 평가가 CHALLENGE 인데 확인된 MFA 가 없으면 들여보내지 않고 실패 횟수는 그대로 둔다`() {
        policy(RiskType.LOGIN, ALWAYS, 30, RiskAction.CHALLENGE)
        val (userId, loginId) = account()

        login(loginId).andExpect(redirectedUrl("/login?challenge"))

        assertEquals(1, loginEvents(userId, "FAILURE", "RISK_CHALLENGE_NO_MFA%"))
        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM login_session WHERE subject_id = ?", Int::class.java, userId))
        assertEquals(0, accountService.findCredential(loginId)?.failedAttemptCount)
    }

    @Test
    fun `로그인에서는 APPROVAL 도 추가 인증으로 다룬다`() {
        policy(RiskType.LOGIN, ALWAYS, 30, RiskAction.APPROVAL)
        val (_, loginId) = account()

        login(loginId).andExpect(redirectedUrl("/login?challenge"))
    }

    @Test
    fun `위험 평가가 CHALLENGE 이고 확인된 MFA 가 있으면 MFA 단계로 보내고 추가 인증 요구를 남긴다`() {
        policy(RiskType.LOGIN, ALWAYS, 30, RiskAction.CHALLENGE)
        val (userId, loginId) = account()
        enrollTotp(userId, loginId)

        login(loginId).andExpect(redirectedUrl("/login/mfa"))

        assertEquals(1, loginEvents(userId, "CHALLENGE", "RISK_CHALLENGE:%"))
        assertEquals(1, jdbc.queryForObject("SELECT COUNT(*) FROM login_session WHERE subject_id = ?", Int::class.java, userId))
    }

    @Test
    fun `설정한 CIDR 대역으로 국가를 찾아 허용 국가 밖이면 FOREIGN_IP 를 잡는다`() {
        policy(RiskType.LOGIN, """{"signal":"FOREIGN_IP","allowedCountries":["KR"]}""", 50, RiskAction.CHALLENGE)
        val userId = fixture.user()

        val foreign = riskEngine.evaluate(RiskContext(userId, RiskType.LOGIN, ipAddress = "203.0.113.10"))
        val unknown = riskEngine.evaluate(RiskContext(userId, RiskType.LOGIN, ipAddress = "198.51.100.10"))

        assertEquals(RiskSignalType.FOREIGN_IP, foreign.signals.single().type)
        assertEquals("US", foreign.signals.single().details["country"])
        assertEquals(RiskAction.CHALLENGE, foreign.decision)
        assertTrue(unknown.signals.isEmpty())
    }

    @Test
    fun `해외 IP 로 로그인하면 FOREIGN_IP 로 추가 인증을 요구한다`() {
        policy(RiskType.LOGIN, """{"signal":"FOREIGN_IP","allowedCountries":["KR"]}""", 50, RiskAction.CHALLENGE)
        val (userId, loginId) = account()

        login(loginId, remoteAddr = "203.0.113.7").andExpect(redirectedUrl("/login?challenge"))

        assertEquals(listOf(RiskSignalType.FOREIGN_IP), signalRepository.findBySubjectIdOrderByDetectedAtDesc(userId).map { it.signalType })
    }

    @Test
    fun `IP 국가 판별기는 CIDR 대역을 먼저 보고, DB 가 없거나 사설·잘못된 주소면 모른다`() {
        val resolver = ConfiguredIpLocationResolver(mapOf("10.1.0.0/16" to "kr", "2001:db8::/32" to "JP", "192.0.2.1" to "US"), null)

        assertEquals("KR", resolver.countryOf("10.1.200.3"))
        assertNull(resolver.countryOf("10.2.0.1"))
        assertEquals("JP", resolver.countryOf("2001:db8::1"))
        assertEquals("US", resolver.countryOf("192.0.2.1"))
        assertNull(resolver.countryOf("192.0.2.2"))
        assertNull(resolver.countryOf("example.com"))
        assertNull(resolver.countryOf(""))
        val cidr = ConfiguredIpLocationResolver.Cidr.parse("172.16.0.0/12")
        assertTrue(cidr.contains(InetAddress.getByName("172.31.255.255")))
        assertFalse(cidr.contains(InetAddress.getByName("172.32.0.0")))
    }

    @Test
    fun `접근 요청의 위험 등급은 역할 성격과 상황 평가 중 높은 쪽이고 평가가 요청에 연결된다`() {
        policy(RiskType.JIT, ALWAYS, 60, RiskAction.APPROVAL)
        val now = Instant.now()

        val request = accessRequestService.requestJit(fixture.user(), fixture.role().requireId(), "점검", now, now.plusSeconds(3600))

        assertEquals(RiskLevel.HIGH, request.riskLevel)
        assertEquals(60, assessmentRepository.findByRequestId(request.requireId())?.riskScore)
    }

    private fun account(): Pair<Long, String> {
        val userId = fixture.user()
        val loginId = "risk${System.nanoTime()}"
        accountService.createAccount(userId, loginId, PASSWORD)
        return userId to loginId
    }

    private fun enrollTotp(userId: Long, loginId: String) {
        val enrollment = mfaService.enrollTotp(userId, loginId)
        val reference = mfaMethodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        mfaService.confirmTotp(userId, enrollment.methodId, Totp.code(secretStore.load(reference), Instant.now()))
    }

    private fun login(loginId: String, remoteAddr: String = "127.0.0.1") =
        mockMvc.perform(
            post("/login").param("username", loginId).param("password", PASSWORD).with(csrf())
                .with { it.apply { this.remoteAddr = remoteAddr } },
        )

    private fun loginEvents(subjectId: Long, result: String, reasonPattern: String): Int? =
        jdbc.queryForObject(
            "SELECT COUNT(*) FROM authentication_event WHERE subject_id = ? AND event_type = 'LOGIN' AND result = ? AND failure_reason LIKE ?",
            Int::class.java, subjectId, result, reasonPattern,
        )

    private fun policy(type: RiskType, condition: String, score: Int, action: RiskAction) =
        policyRepository.save(RiskPolicy("테스트 $type $score", type, condition, score, action))

    companion object {
        /** from == to 면 하루 전체가 범위 밖이라 늘 잡힌다 */
        const val ALWAYS = """{"signal":"UNUSUAL_TIME","from":"00:00","to":"00:00"}"""
        const val PASSWORD = "correct-horse-battery"
    }
}
