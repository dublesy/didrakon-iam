package com.didrakon.iam.api

import com.didrakon.iam.api.support.ApiResources
import com.didrakon.iam.authn.apikey.ApiKeyService
import com.didrakon.iam.authn.credential.LocalAccountService
import com.didrakon.iam.authz.AuthzFixture
import com.didrakon.iam.authz.IntegrationTest
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.authz.role.RoleRepository
import com.didrakon.iam.config.IamBootstrap
import com.didrakon.iam.identity.organization.OrgType
import com.didrakon.iam.identity.organization.OrganizationService
import com.didrakon.iam.identity.organization.SubjectOrganizationRepository
import com.didrakon.iam.identity.subject.EmploymentStatus
import com.didrakon.iam.identity.subject.Environment
import com.didrakon.iam.identity.subject.ServiceAccount
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserKind
import com.didrakon.iam.identity.subject.UserRepository
import com.didrakon.iam.identity.subject.UserService
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.http.MediaType
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.core.authority.SimpleGrantedAuthority
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.ResultActions
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.time.LocalDate
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * HR 연동 API. 레코드마다 새 트랜잭션으로 커밋하므로 롤백 테스트(@AuthzTest)가 아니라 커밋되는 통합 테스트로 하고,
 * 사번·조직 코드는 테스트마다 새로 만든다.
 */
@IntegrationTest
class HrSyncApiTests @Autowired constructor(
    private val mockMvc: MockMvc,
    private val fixture: AuthzFixture,
    private val roleRepository: RoleRepository,
    private val assignmentService: RoleAssignmentService,
    private val organizationService: OrganizationService,
    private val userRepository: UserRepository,
    private val subjectRepository: SubjectRepository,
    private val membershipRepository: SubjectOrganizationRepository,
    private val accountService: LocalAccountService,
    private val apiKeyService: ApiKeyService,
    private val jdbc: JdbcTemplate,
    private val userService: UserService,
) {
    private val sequence = AtomicLong()

    @Test
    fun `처음 보는 사번은 사용자와 주 소속을 만들고 로그인 계정은 만들지 않는다`() {
        val org = org()
        val empNo = code("EMP")

        sync(employee(empNo, org, extra = """"email":"hr@example.com","jobTitle":"매니저","isManager":true"""))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.dryRun").value(false))
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("CREATED"))
            .andExpect(jsonPath("$.data.counts.CREATED").value(1))

        val user = user(empNo)
        assertEquals("hr@example.com", user.email)
        val primary = membershipRepository.findActivePrimary(user.requireId()) ?: throw AssertionError("주 소속 없음")
        assertEquals(orgId(org), primary.orgId)
        assertEquals("매니저", primary.jobTitle)
        assertTrue(primary.isManager)
        assertNull(accountService.findLocalIdentity(user.requireId()))
    }

    @Test
    fun `주 소속 조직이 바뀌면 전적 처리되고 같은 조직이면 직위만 고친다`() {
        val companyA = org(OrgType.COMPANY)
        val companyB = org(OrgType.COMPANY)
        val empNo = code("EMP")
        sync(employee(empNo, companyA)).andExpect(status().isOk)
        val subjectId = user(empNo).requireId()
        val globalRole = assignmentService.assignDirect(subjectId, fixture.role().requireId()).requireId()

        sync(employee(empNo, companyB, extra = """"jobTitle":"팀장""""))
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("TRANSFERRED"))
        val primary = membershipRepository.findActivePrimary(subjectId) ?: throw AssertionError("주 소속 없음")
        assertEquals(orgId(companyB), primary.orgId)
        assertEquals("팀장", primary.jobTitle)
        assertEquals(true, jdbc.queryForObject("SELECT review_required FROM role_assignment WHERE assignment_id = ?", Boolean::class.java, globalRole))

        sync(employee(empNo, companyB, extra = """"jobGrade":"G3""""))
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("MEMBERSHIP_UPDATED"))
        assertEquals("G3", membershipRepository.findActivePrimary(subjectId)?.jobGrade)
        assertEquals(
            1,
            jdbc.queryForObject(
                "SELECT COUNT(*) FROM audit_event WHERE resource_type = 'SUBJECT_ORGANIZATION' AND action = 'UPDATE' AND target_subject_id = ?",
                Int::class.java, subjectId,
            ),
        )
    }

    @Test
    fun `휴직이면 사용 중지되어 API 키가 회수되고 재직으로 돌아오면 다시 사용된다`() {
        val org = org()
        val empNo = code("EMP")
        sync(employee(empNo, org)).andExpect(status().isOk)
        val subjectId = user(empNo).requireId()
        val key = apiKeyService.issue(subjectId, "개인 배치").rawKey

        sync(employee(empNo, org, status = "LEAVE")).andExpect(jsonPath("$.data.records[0].actions[0]").value("ON_LEAVE"))
        user(empNo).let {
            assertEquals(SubjectStatus.DISABLED, it.status)
            assertEquals(EmploymentStatus.LEAVE, it.employmentStatus)
        }
        assertNull(apiKeyService.authenticate(key))

        sync(employee(empNo, org)).andExpect(jsonPath("$.data.records[0].actions[0]").value("RETURNED"))
        user(empNo).let {
            assertEquals(SubjectStatus.ACTIVE, it.status)
            assertEquals(EmploymentStatus.EMPLOYED, it.employmentStatus)
        }
        sync(employee(empNo, org)).andExpect(jsonPath("$.data.records[0].actions[0]").value("UNCHANGED"))
    }

    @Test
    fun `퇴사면 퇴사 처리하고 미래 퇴사일은 예약했다가 빠지면 취소한다`() {
        val org = org()
        val retiring = code("EMP")
        val scheduled = code("EMP")
        val future = LocalDate.now().plusDays(30)
        sync(employee(retiring, org), employee(scheduled, org)).andExpect(status().isOk)

        sync(
            employee(retiring, org, status = "RETIRED"),
            employee(scheduled, org, extra = """"retireDate":"$future""""),
        )
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("RETIRED"))
            .andExpect(jsonPath("$.data.records[1].actions[0]").value("RETIRE_SCHEDULED"))
        assertEquals(SubjectStatus.RETIRED, user(retiring).status)
        assertNull(membershipRepository.findActivePrimary(user(retiring).requireId()))
        user(scheduled).let {
            assertEquals(SubjectStatus.ACTIVE, it.status)
            assertEquals(future, it.retireDate)
        }

        sync(employee(retiring, org, status = "RETIRED"), employee(scheduled, org))
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("UNCHANGED"))
            .andExpect(jsonPath("$.data.records[1].actions[0]").value("RETIRE_CANCELLED"))
        assertNull(user(scheduled).retireDate)
    }

    @Test
    fun `미리보기는 할 일만 알려주고 아무것도 바꾸지 않지만 실행 기록은 남긴다`() {
        val org = org()
        val existing = code("EMP")
        val newcomer = code("EMP")
        sync(employee(existing, org)).andExpect(status().isOk)

        val body = sync(employee(newcomer, org), employee(existing, org, status = "LEAVE"), dryRun = true)
            .andExpect(jsonPath("$.data.dryRun").value(true))
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("CREATED"))
            .andExpect(jsonPath("$.data.records[1].actions[0]").value("ON_LEAVE"))
            .andReturn().response.contentAsString

        assertNull(userRepository.findByEmpNo(newcomer))
        assertEquals(SubjectStatus.ACTIVE, user(existing).status)
        val runId = Regex("\"runId\":(\\d+)").find(body)?.groupValues?.get(1) ?: throw AssertionError(body)
        mockMvc.perform(get("/api/v1/hr/sync-runs").with(person(admin())))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data[0].runId").value(runId.toLong()))
            .andExpect(jsonPath("$.data[0].dryRun").value(true))
            .andExpect(jsonPath("$.data[0].total").value(2))
            .andExpect(jsonPath("$.data[0].counts.CREATED").value(1))
    }

    @Test
    fun `잘못된 레코드는 그 레코드만 오류로 돌려주고 나머지는 반영한다`() {
        val org = org()
        val good = code("EMP")
        val badOrg = code("EMP")
        val badStatus = code("EMP")

        sync(
            employee(badOrg, "NO-SUCH-ORG-${System.nanoTime()}"),
            employee(good, org),
            employee(badStatus, org, status = "FIRED"),
            employee(good, org),
        )
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("ERROR"))
            .andExpect(jsonPath("$.data.records[1].actions[0]").value("CREATED"))
            .andExpect(jsonPath("$.data.records[2].actions[0]").value("ERROR"))
            .andExpect(jsonPath("$.data.records[3].actions[0]").value("ERROR"))
            .andExpect(jsonPath("$.data.counts.ERROR").value(3))

        assertNull(userRepository.findByEmpNo(badOrg))
        assertNull(userRepository.findByEmpNo(badStatus))
        assertNotNull(userRepository.findByEmpNo(good))
        val errors = jdbc.queryForObject("SELECT errors FROM hr_sync_run ORDER BY run_id DESC LIMIT 1", String::class.java).orEmpty()
        assertTrue(badOrg in errors && badStatus in errors, errors)
    }

    @Test
    fun `피드에 없는 사용 중 사용자를 알려주기만 하고 퇴사시키지 않는다`() {
        val org = org()
        val present = code("EMP")
        val absent = code("EMP")
        sync(employee(present, org), employee(absent, org)).andExpect(status().isOk)

        val body = sync(employee(present, org), reportMissing = true)
            .andExpect(status().isOk)
            .andReturn().response.contentAsString

        assertTrue("\"empNo\":\"$absent\"" in body.substringAfter("\"missing\""), body)
        assertFalse("\"empNo\":\"$present\"" in body.substringAfter("\"missing\""), body)
        assertEquals(SubjectStatus.ACTIVE, user(absent).status)
    }

    @Test
    fun `외부 사용자는 HR 연동이 건드리지 않고 피드에 없는 사용자로도 보고하지 않는다`() {
        val org = org()
        val external = userService.create(
            null, "고객사 담당자", "${code("ext")}@customer.example.com", null, null, UserKind.EXTERNAL, orgId(org),
        ).requireId()

        val body = sync(employee(code("EMP"), org), reportMissing = true)
            .andExpect(status().isOk)
            .andReturn().response.contentAsString

        assertFalse("\"subjectId\":$external," in body.substringAfter("\"missing\""), body)
        val user = userRepository.findById(external).orElseThrow()
        assertEquals(SubjectStatus.ACTIVE, user.status)
        assertEquals("고객사 담당자", user.name)
        assertNull(user.empNo)
    }

    @Test
    fun `HR 연동 역할 서비스 계정 API 키나 scope 토큰으로 부를 수 있고 권한 없는 사용자는 거부된다`() {
        val org = org()
        val service = subjectRepository.save(ServiceAccount("hr-system", fixture.user(), Environment.PROD)).requireId()
        val role = roleRepository.findByRoleCode(IamBootstrap.HR_SYNC_ROLE) ?: throw AssertionError("IAM_HR_SYNC 역할 없음")
        assignmentService.assignDirect(service, role.requireId())
        val key = apiKeyService.issue(service, "인사 연동").rawKey
        val body = """{"employees":[${employee(code("EMP"), org)}]}"""

        mockMvc.perform(json(post("/api/v1/hr/sync?dryRun=true"), body).header("X-API-Key", key))
            .andExpect(status().isOk)
            .andExpect(jsonPath("$.data.records[0].actions[0]").value("CREATED"))
        mockMvc.perform(get("/api/v1/hr/sync-runs").header("X-API-Key", key)).andExpect(status().isOk)
        mockMvc.perform(
            json(post("/api/v1/hr/sync?dryRun=true"), body)
                .with(jwt().jwt { it.subject("hr-client") }.authorities(SimpleGrantedAuthority("SCOPE_${ApiResources.HR_SYNC_SCOPE}"))),
        ).andExpect(status().isOk)
        mockMvc.perform(json(post("/api/v1/hr/sync?dryRun=true"), body).with(person(fixture.user())))
            .andExpect(status().isForbidden)
    }

    private fun sync(vararg employees: String, dryRun: Boolean = false, reportMissing: Boolean = false): ResultActions =
        mockMvc.perform(
            json(post("/api/v1/hr/sync?dryRun=$dryRun"), """{"employees":[${employees.joinToString(",")}],"reportMissing":$reportMissing}""")
                .with(person(admin())),
        )

    private fun employee(empNo: String, orgCode: String, status: String = "EMPLOYED", extra: String = ""): String =
        """{"empNo":"$empNo","name":"직원 $empNo","orgCode":"$orgCode","employmentStatus":"$status"${if (extra.isEmpty()) "" else ",$extra"}}"""

    private fun org(type: OrgType = OrgType.DEPARTMENT): String = code("HR-ORG").also { organizationService.create(it, "조직 $it", type, null) }

    private fun orgId(orgCode: String): Long =
        jdbc.queryForObject("SELECT org_id FROM organization WHERE org_code = ?", Long::class.java, orgCode) ?: throw AssertionError(orgCode)

    private fun user(empNo: String): User = userRepository.findByEmpNo(empNo) ?: throw AssertionError("사용자 없음: $empNo")

    private fun code(prefix: String) = "$prefix-${sequence.incrementAndGet()}-${System.nanoTime()}"

    private fun admin(): Long = fixture.user("관리자").also {
        assignmentService.assignDirect(it, roleRepository.findByRoleCode(IamBootstrap.ADMIN_ROLE)?.requireId() ?: throw AssertionError())
    }

    private fun person(subjectId: Long) = jwt().jwt { it.subject(subjectId.toString()).claim("amr", listOf("pwd", "otp")) }

    private fun json(builder: MockHttpServletRequestBuilder, body: String) = builder.contentType(MediaType.APPLICATION_JSON).content(body)
}
