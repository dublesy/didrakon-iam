package com.didrakon.iam.schema

import com.didrakon.iam.TestcontainersConfiguration
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.dao.DataAccessException
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional
import kotlin.test.assertContains
import kotlin.test.assertEquals

/** ERD 문서 4절 "ERD에 표현되지 않는 제약"이 DB 에서 실제로 막히는지 확인한다 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
@Transactional
class SchemaConstraintTests @Autowired constructor(
    private val jdbc: JdbcTemplate,
) {
    @Test
    fun `ERD 의 테이블 53개와 운영용 테이블이 모두 생성된다`() {
        val count = jdbc.queryForObject(
            """
            SELECT COUNT(*) FROM information_schema.tables
            WHERE table_schema = DATABASE() AND table_name <> 'flyway_schema_history'
            """,
            Int::class.java,
        )

        assertEquals(53 + 13, count) // + secret_value (V7), shedlock (V8), login_session_authorization (V10), rate_limit_counter (V12), hr_sync_run (V14), webhook_subscription·webhook_delivery (V15), access_review_campaign·access_review_item (V16), user_entities·user_credentials (V18), SPRING_SESSION·SPRING_SESSION_ATTRIBUTES (V22)
    }

    @Test
    fun `GLOBAL scope 행이 미리 들어 있다`() {
        val type = jdbc.queryForObject("SELECT scope_type FROM scope WHERE scope_code = 'GLOBAL'", String::class.java)

        assertEquals("GLOBAL", type)
    }

    @Test
    fun `활성 PRIMARY 소속은 subject 당 1개만 허용된다`() {
        val subjectId = insertSubject()
        val orgA = insertOrganization("ORG-A")
        val orgB = insertOrganization("ORG-B")
        insertMembership(subjectId, orgA, "PRIMARY")

        val error = assertThrows<DataAccessException> { insertMembership(subjectId, orgB, "PRIMARY") }

        assertContains(error.message.orEmpty(), "uk_subject_organization_active_primary")
    }

    @Test
    fun `종료된 PRIMARY 소속과 겸직 소속은 새 PRIMARY 소속을 막지 않는다`() {
        val subjectId = insertSubject()
        val orgA = insertOrganization("ORG-A")
        val orgB = insertOrganization("ORG-B")
        insertMembership(subjectId, orgA, "PRIMARY", validUntil = "2026-01-01")
        insertMembership(subjectId, orgA, "SECONDARY")

        insertMembership(subjectId, orgB, "PRIMARY")
    }

    @Test
    fun `정책 대상은 권한·리소스·역할 중 정확히 하나여야 한다`() {
        val policyId = insertPolicy()
        val roleId = insertRole("ROLE-A")

        val none = assertThrows<DataAccessException> {
            jdbc.update("INSERT INTO policy_target (policy_id) VALUES (?)", policyId)
        }
        assertContains(none.message.orEmpty(), "ck_policy_target_one_target")

        jdbc.update("INSERT INTO policy_target (policy_id, role_id) VALUES (?, ?)", policyId, roleId)
    }

    @Test
    fun `정책 예외는 대상 subject 나 리소스가 있어야 한다`() {
        val policyId = insertPolicy()

        val error = assertThrows<DataAccessException> {
            jdbc.update(
                "INSERT INTO policy_exception (policy_id, reason, valid_from) VALUES (?, '사유', NOW(6))",
                policyId,
            )
        }

        assertContains(error.message.orEmpty(), "ck_policy_exception_has_target")
    }

    @Test
    fun `subject 관계의 대상은 subject 와 리소스 중 하나만 둔다`() {
        val subjectId = insertSubject()
        val targetId = insertSubject()
        jdbc.update("INSERT INTO relation_type (relation_code, relation_name) VALUES ('MANAGES', '관리')")
        val relationTypeId = lastInsertId()

        val none = assertThrows<DataAccessException> {
            jdbc.update(
                "INSERT INTO subject_relation (subject_id, relation_type_id, valid_from) VALUES (?, ?, NOW(6))",
                subjectId, relationTypeId,
            )
        }
        assertContains(none.message.orEmpty(), "ck_subject_relation_one_target")

        jdbc.update(
            "INSERT INTO subject_relation (subject_id, relation_type_id, target_subject_id, valid_from) VALUES (?, ?, ?, NOW(6))",
            subjectId, relationTypeId, targetId,
        )
    }

    @Test
    fun `역할 충돌은 작은 역할 ID 를 a 에 두어야 한다`() {
        val small = insertRole("ROLE-A")
        val large = insertRole("ROLE-B")

        val reversed = assertThrows<DataAccessException> {
            jdbc.update("INSERT INTO role_conflict (role_id_a, role_id_b, severity) VALUES (?, ?, 'HIGH')", large, small)
        }
        assertContains(reversed.message.orEmpty(), "ck_role_conflict_order")

        jdbc.update("INSERT INTO role_conflict (role_id_a, role_id_b, severity) VALUES (?, ?, 'HIGH')", small, large)
    }

    private fun insertSubject(): Long {
        jdbc.update(
            """
            INSERT INTO subject (subject_type, subject_name, status, created_at, updated_at)
            VALUES ('USER', '테스트', 'ACTIVE', NOW(6), NOW(6))
            """,
        )
        return lastInsertId()
    }

    private fun insertOrganization(code: String): Long {
        jdbc.update(
            """
            INSERT INTO organization (org_code, org_name, org_type, org_level, created_at, updated_at)
            VALUES (?, ?, 'COMPANY', 1, NOW(6), NOW(6))
            """,
            code, code,
        )
        return lastInsertId()
    }

    private fun insertMembership(subjectId: Long, orgId: Long, type: String, validUntil: String? = null) {
        jdbc.update(
            """
            INSERT INTO subject_organization (subject_id, org_id, membership_type, valid_from, valid_until)
            VALUES (?, ?, ?, '2025-01-01', ?)
            """,
            subjectId, orgId, type, validUntil,
        )
    }

    private fun insertPolicy(): Long {
        jdbc.update(
            """
            INSERT INTO policy (policy_code, policy_name, policy_type, effect, created_at, updated_at)
            VALUES ('POLICY-A', '정책', 'AUTHORIZATION', 'DENY', NOW(6), NOW(6))
            """,
        )
        return lastInsertId()
    }

    private fun insertRole(code: String): Long {
        jdbc.update(
            """
            INSERT INTO role (role_code, role_name, role_type, created_at, updated_at)
            VALUES (?, ?, 'BUSINESS', NOW(6), NOW(6))
            """,
            code, code,
        )
        return lastInsertId()
    }

    private fun lastInsertId(): Long =
        jdbc.queryForObject("SELECT LAST_INSERT_ID()", Long::class.java)
            ?: throw IllegalStateException("LAST_INSERT_ID 조회 실패")
}
