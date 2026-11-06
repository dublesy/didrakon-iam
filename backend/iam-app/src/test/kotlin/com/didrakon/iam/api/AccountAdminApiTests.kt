package com.didrakon.iam.api

import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authn.mfa.MfaMethodRepository
import com.didrakon.iam.authn.mfa.MfaService
import com.didrakon.iam.authn.mfa.SecretStore
import com.didrakon.iam.authn.mfa.Totp
import com.didrakon.iam.authn.session.AuthenticationLevel
import com.didrakon.iam.authn.session.LoginSessionService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.AuthzTest
import com.didrakon.iam.authz.assignment.RoleAssignmentRepository
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.AuthzCatalogService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.authz.scope.ScopeType
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.organization.OrgType
import com.jayway.jsonpath.JsonPath
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.Instant
import java.time.temporal.ChronoUnit
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 사용자 상세의 헬프데스크 일: 로그인 계정 만들기, 2단계 인증 초기화, API 키, 모든 세션 끊기, 직접 할당 기간 변경. 테스트마다 롤백된다 */
@AuthzTest
class AccountAdminApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val assignmentRepository: RoleAssignmentRepository,
    private val catalogService: AuthzCatalogService,
    private val accountService: LocalAccountService,
    private val mfaService: MfaService,
    private val methodRepository: MfaMethodRepository,
    private val secretStore: SecretStore,
    private val sessionService: LoginSessionService,
    private val jdbc: JdbcTemplate,
) {
    private val password = "correct-horse-battery"

    /** 범위 조직 안 사용자(userIn), 범위 밖 사용자(userOut), 같은 조직의 다른 조직 단위 관리자(peer) */
    private inner class World {
        val scopeOrg = fixture.org(OrgType.DIVISION)
        val otherOrg = fixture.org(OrgType.DIVISION)
        val orgAdmin = orgAdmin(scopeOrg)
        val peer = orgAdmin(scopeOrg)
        val userIn = fixture.user().also { fixture.join(it, scopeOrg) }
        val userOut = fixture.user().also { fixture.join(it, otherOrg) }
    }

    @Test
    fun `로그인 계정이 없는 사용자에게 계정을 만들면 다음 로그인에서 비밀번호를 바꿔야 하고, 조직 단위 관리자는 범위 안 일반 사용자에게만 만든다`() {
        val w = World()
        fun create(target: Long, actor: Long) =
            json(post("/api/v1/users/$target/login-account"), actor, """{"loginId":"acct${System.nanoTime()}","password":"$password"}""")

        create(w.userOut, w.orgAdmin).andExpect(status().isForbidden)
        create(w.peer, w.orgAdmin).andExpect(status().isForbidden)
        create(w.userIn, w.orgAdmin).andExpect(status().isCreated)
            .andExpect(jsonPath("$.data.loginId").exists())
            .andExpect(jsonPath("$.data.mustChangePassword").value(true))
            .andExpect(jsonPath("$.data.passwordChangedAt").exists())
            .andExpect(jsonPath("$.data.passwordHash").doesNotExist())
        assertTrue(accountService.findLocalCredential(w.userIn)?.mustChangePassword ?: false)

        // 이미 있으면 다시 만들지 않는다
        create(w.userIn, w.orgAdmin).andExpect(status().isConflict)
        assertEquals(1, auditCount("USER", w.userIn, "CREATE_LOGIN_ACCOUNT"))
    }

    @Test
    fun `사용자를 만들며 정한 첫 비밀번호도 다음 로그인에서 바꿔야 한다`() {
        val w = World()
        val loginId = "reg${System.nanoTime()}"
        val created = json(
            post("/api/v1/users"), w.orgAdmin,
            """{"empNo":"E${System.nanoTime()}","name":"새 직원","primaryOrgId":${w.scopeOrg},"loginId":" $loginId ","password":"$password"}""",
        ).andExpect(status().isCreated)
        val subjectId = JsonPath.read<Number>(body(created), "$.data.subjectId").toLong()

        val credential = accountService.findLocalCredential(subjectId) ?: throw AssertionError("로그인 계정 없음")
        assertTrue(credential.mustChangePassword, "관리자가 정한 비밀번호를 계속 쓰지 못하게 한다")
        assertEquals(subjectId, accountService.findIdentity(loginId)?.subjectId, "로그인 ID 앞뒤 공백은 지운다")
    }

    @Test
    fun `2단계 인증 수단을 보고 초기화한다 - 비밀값은 주지 않고, 조직 단위 관리자는 범위 밖과 다른 관리자를 초기화할 수 없다`() {
        val w = World()
        val methodIn = totp(w.userIn)
        val methodOut = totp(w.userOut)
        val methodPeer = totp(w.peer)

        val listed = body(
            mockMvc.perform(get("/api/v1/subjects/${w.userIn}/mfa").with(user(w.orgAdmin))).andExpect(status().isOk)
                .andExpect(jsonPath("$.data.methods[0].methodId").value(methodIn))
                .andExpect(jsonPath("$.data.methods[0].methodType").value("TOTP"))
                .andExpect(jsonPath("$.data.passkeys.length()").value(0)),
        )
        assertFalse(listed.contains("secret", ignoreCase = true), listed)
        mockMvc.perform(get("/api/v1/subjects/${w.userOut}/mfa").with(user(w.orgAdmin))).andExpect(status().isForbidden)

        mockMvc.perform(delete("/api/v1/subjects/${w.userOut}/mfa/$methodOut").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(delete("/api/v1/subjects/${w.peer}/mfa/$methodPeer").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        // 다른 사람의 수단 ID 를 경로에 섞어도 지워지지 않는다
        mockMvc.perform(delete("/api/v1/subjects/${w.userIn}/mfa/$methodOut").with(user(w.orgAdmin))).andExpect(status().isNotFound)
        mockMvc.perform(delete("/api/v1/subjects/${w.userIn}/mfa/passkeys/unknown").with(user(w.orgAdmin))).andExpect(status().isNotFound)

        mockMvc.perform(delete("/api/v1/subjects/${w.userIn}/mfa/$methodIn").with(user(w.orgAdmin))).andExpect(status().isOk)
        assertFalse(mfaService.hasVerifiedMethod(w.userIn))
        assertTrue(mfaService.hasVerifiedMethod(w.userOut))
        assertTrue(mfaService.hasVerifiedMethod(w.peer))
        assertEquals(1, auditCount("USER", w.userIn, "MFA_RESET"))
    }

    @Test
    fun `모든 세션 끊기는 그 사람의 로그인 세션을 모두 끝내고, 조직 단위 관리자는 범위 밖과 다른 관리자에게 쓸 수 없다`() {
        val w = World()
        listOf(w.userIn, w.userOut, w.peer).forEach { openSessions(it, 2) }

        mockMvc.perform(delete("/api/v1/subjects/${w.userOut}/sessions").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(delete("/api/v1/subjects/${w.peer}/sessions").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(delete("/api/v1/subjects/${w.userIn}/sessions").with(user(w.orgAdmin)))
            .andExpect(status().isOk).andExpect(jsonPath("$.data.revokedSessions").value(2))

        assertEquals(0, sessionService.activeSessions(w.userIn).size)
        assertEquals(2, sessionService.activeSessions(w.userOut).size)
        assertEquals(2, sessionService.activeSessions(w.peer).size)
        assertEquals(1, auditCount("USER", w.userIn, "REVOKE_SESSIONS"))
    }

    @Test
    fun `API 키 목록은 키 원문과 hash 를 주지 않고, 발급·폐기는 누가 했는지 감사 기록에 남는다`() {
        val w = World()
        val admin = globalAdmin()

        val issued = body(
            json(post("/api/v1/subjects/${w.userIn}/api-keys"), admin, """{"keyName":"배치 연동"}""").andExpect(status().isCreated),
        )
        val apiKeyId = JsonPath.read<Number>(issued, "$.data.apiKeyId").toLong()
        val rawKey = JsonPath.read<String>(issued, "$.data.rawKey")

        val listed = body(
            mockMvc.perform(get("/api/v1/subjects/${w.userIn}/api-keys").with(user(admin))).andExpect(status().isOk)
                .andExpect(jsonPath("$.data[0].apiKeyId").value(apiKeyId))
                .andExpect(jsonPath("$.data[0].keyName").value("배치 연동"))
                .andExpect(jsonPath("$.data[0].revoked").value(false))
                .andExpect(jsonPath("$.data[0].revokedAt").doesNotExist()),
        )
        assertFalse(listed.contains(rawKey), listed)
        assertFalse(listed.contains("hash", ignoreCase = true), listed)
        assertFalse(listed.contains("rawKey"), listed)

        // API 키 권한은 조직 단위 관리자에게 없다
        mockMvc.perform(get("/api/v1/subjects/${w.userIn}/api-keys").with(user(w.orgAdmin))).andExpect(status().isForbidden)

        mockMvc.perform(delete("/api/v1/api-keys/$apiKeyId").with(user(admin))).andExpect(status().isOk)
        val revokedAt = JsonPath.read<String>(
            body(
                mockMvc.perform(get("/api/v1/subjects/${w.userIn}/api-keys").with(user(admin)))
                    .andExpect(jsonPath("$.data[0].revoked").value(true))
                    .andExpect(jsonPath("$.data[0].revokedAt").exists()),
            ),
            "$.data[0].revokedAt",
        )
        assertTrue(Instant.parse(revokedAt).isAfter(Instant.now().minusSeconds(60)), revokedAt)
        assertEquals(admin, jdbc.queryForObject("SELECT revoked_by FROM api_key WHERE api_key_id = ?", Long::class.java, apiKeyId))

        val audited = jdbc.queryForList(
            "SELECT actor_subject_id, target_subject_id, action, after_value FROM audit_event WHERE resource_type = 'API_KEY' AND resource_id = ? ORDER BY event_id",
            apiKeyId.toString(),
        )
        assertEquals(listOf("ISSUE", "REVOKE"), audited.map { it["action"] })
        assertTrue(audited.all { (it["actor_subject_id"] as Number).toLong() == admin })
        // 키 소유자가 감사 대상 사람으로 남아, 사람으로 감사 기록을 찾으면 나온다
        assertTrue(audited.all { (it["target_subject_id"] as Number?)?.toLong() == w.userIn }, audited.toString())
        val from = Instant.now().minus(1, ChronoUnit.HOURS)
        val to = Instant.now().plus(1, ChronoUnit.HOURS)
        val found = body(
            mockMvc.perform(get("/api/v1/audit/events?from=$from&to=$to&subjectId=${w.userIn}").with(user(admin))).andExpect(status().isOk),
        )
        val apiKeyActions = JsonPath.read<List<String>>(found, "$.data[?(@.resourceType == 'API_KEY' && @.resourceId == '$apiKeyId')].action")
        assertEquals(setOf("ISSUE", "REVOKE"), apiKeyActions.toSet())
        assertTrue(audited.all { it["after_value"].toString().contains("배치 연동") && !it["after_value"].toString().contains(rawKey) })
    }

    @Test
    fun `직접 할당의 종료 시각을 바꾸면 효력 기간이 바뀌고 이력이 남는다`() {
        val w = World()
        val admin = globalAdmin()
        val roleId = fixture.role().requireId()
        val until = Instant.now().plus(30, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS)
        val assignment = assignmentService.assignDirect(w.userIn, roleId, validUntil = until).requireId()
        val later = Instant.now().plus(10, ChronoUnit.DAYS)
        val shorter = Instant.now().plus(1, ChronoUnit.DAYS).truncatedTo(ChronoUnit.SECONDS)

        json(put("/api/v1/assignments/$assignment"), w.orgAdmin, """{"validUntil":"$shorter"}""").andExpect(status().isForbidden)
        json(put("/api/v1/assignments/$assignment"), admin, """{"validUntil":"${Instant.now().minusSeconds(60)}"}""").andExpect(status().isConflict)

        assertTrue(assignmentRepository.findEffective(w.userIn, later).any { it.requireId() == assignment })
        json(put("/api/v1/assignments/$assignment"), admin, """{"validUntil":"$shorter","reason":"프로젝트 단축"}""")
            .andExpect(status().isOk).andExpect(jsonPath("$.data.validUntil").value(shorter.toString()))
        assertFalse(assignmentRepository.findEffective(w.userIn, later).any { it.requireId() == assignment })
        assertTrue(assignmentRepository.findEffective(w.userIn, Instant.now()).any { it.requireId() == assignment })

        // 기한 없음으로 되돌리기
        json(put("/api/v1/assignments/$assignment"), admin, """{"validUntil":null}""")
            .andExpect(status().isOk).andExpect(jsonPath("$.data.validUntil").doesNotExist())
        assertTrue(assignmentRepository.findEffective(w.userIn, later).any { it.requireId() == assignment })

        val history = jdbc.queryForList(
            "SELECT changed_by, reason FROM role_change_history WHERE assignment_id = ? AND change_type = 'MODIFY' ORDER BY history_id", assignment,
        )
        assertEquals(2, history.size)
        assertEquals(admin, (history[0]["changed_by"] as Number).toLong())
        assertTrue(history[0]["reason"].toString().contains("프로젝트 단축"), history[0].toString())
        val audit = jdbc.queryForObject(
            "SELECT COUNT(*) FROM audit_event WHERE resource_type = 'ROLE_ASSIGNMENT' AND resource_id = ? AND action = 'MODIFY'",
            Int::class.java, assignment.toString(),
        )
        assertEquals(2, audit)
    }

    @Test
    fun `직접 할당이 아니면 기간을 바꿀 수 없다`() {
        val admin = globalAdmin()
        val org = fixture.org(OrgType.TEAM)
        val member = fixture.user().also { fixture.join(it, org) }
        val roleId = fixture.role().requireId()
        json(post("/api/v1/organization-roles"), admin, """{"orgId":$org,"roleId":$roleId}""").andExpect(status().isCreated)
        val viaOrg = assignmentService.effectiveAssignments(member).single { it.roleId == roleId }.requireId()

        json(put("/api/v1/assignments/$viaOrg"), admin, """{"validUntil":"${Instant.now().plus(1, ChronoUnit.DAYS)}"}""").andExpect(status().isConflict)
    }

    @Test
    fun `내 정보는 역할·범위 목록을 볼 권한이 없는 조직 단위 관리자와 일반 사용자에게도 역할·범위 이름을 준다`() {
        val w = World()
        val role = fixture.role()
        assignmentService.assignDirect(w.userIn, role.requireId())

        mockMvc.perform(get("/api/v1/roles").with(user(w.orgAdmin))).andExpect(status().isForbidden)
        mockMvc.perform(get("/api/v1/me").with(user(w.orgAdmin))).andExpect(status().isOk)
            .andExpect(jsonPath("$.data.assignments[?(@.roleCode == '${IamBootstrap.ORG_ADMIN_ROLE}')].roleName").isNotEmpty)
            .andExpect(jsonPath("$.data.assignments[?(@.roleCode == '${IamBootstrap.ORG_ADMIN_ROLE}')].scopeName").value("조직 범위"))
            .andExpect(jsonPath("$.data.assignments[?(@.roleCode == '${IamBootstrap.ORG_ADMIN_ROLE}')].scopeCode").isNotEmpty)
        mockMvc.perform(get("/api/v1/me").with(user(w.userIn))).andExpect(status().isOk)
            .andExpect(jsonPath("$.data.assignments[0].roleId").value(role.requireId().toInt()))
            .andExpect(jsonPath("$.data.assignments[0].roleName").value(role.roleName))
            .andExpect(jsonPath("$.data.assignments[0].roleCode").value(role.roleCode))
            .andExpect(jsonPath("$.data.assignments[0].scopeCode").value("GLOBAL"))
            .andExpect(jsonPath("$.data.assignments[0].sourceType").value("DIRECT"))
    }

    private fun totp(subjectId: Long): Long {
        val enrollment = mfaService.enrollTotp(subjectId, "user$subjectId")
        val reference = methodRepository.findById(enrollment.methodId).orElseThrow().secretReference ?: throw AssertionError()
        mfaService.confirmTotp(subjectId, enrollment.methodId, Totp.code(secretStore.load(reference), Instant.now()))
        return enrollment.methodId
    }

    private fun openSessions(subjectId: Long, count: Int) {
        val identity = accountService.createAccount(subjectId, "s${System.nanoTime()}", password).requireId()
        repeat(count) { sessionService.open("key-${System.nanoTime()}-$it", subjectId, identity, AuthenticationLevel.PASSWORD, null, null) }
    }

    private fun auditCount(resourceType: String, id: Long, action: String): Int = jdbc.queryForObject(
        "SELECT COUNT(*) FROM audit_event WHERE resource_type = ? AND resource_id = ? AND action = ?", Int::class.java, resourceType, id.toString(), action,
    ) ?: 0

    private fun orgAdmin(orgId: Long): Long = fixture.user("조직 관리자").also {
        fixture.join(it, orgId)
        val scope = catalogService.createScope("ORG-ADMIN-${System.nanoTime()}", "조직 범위", ScopeType.ORGANIZATION, orgId = orgId, includeDescendants = true)
        val role = roleRepository.findByRoleCode(IamBootstrap.ORG_ADMIN_ROLE)?.requireId() ?: throw AssertionError("IAM_ORG_ADMIN 역할 없음")
        assignmentService.assignDirect(it, role, scope.requireId())
    }

    private fun globalAdmin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun json(builder: MockHttpServletRequestBuilder, subjectId: Long, body: String) =
        mockMvc.perform(builder.with(user(subjectId)).contentType(MediaType.APPLICATION_JSON).content(body))

    private fun body(result: org.springframework.test.web.servlet.ResultActions): String = result.andReturn().response.contentAsString

    private fun user(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }
}
