package com.didrakon.iam.identity

import com.didrakon.iam.TestcontainersConfiguration
import com.didrakon.iam.common.RiskLevel
import com.didrakon.iam.identity.subject.AiAgent
import com.didrakon.iam.identity.subject.Environment
import com.didrakon.iam.identity.subject.ServiceAccount
import com.didrakon.iam.identity.subject.SubjectRepository
import com.didrakon.iam.identity.subject.SubjectStatus
import com.didrakon.iam.identity.subject.SubjectType
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import jakarta.persistence.EntityManager
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional
import java.time.LocalDate
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull

/** Subject JOINED 상속이 subject_type 판별 컬럼과 하위 테이블에 맞게 저장·조회되는지 확인한다 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
@Transactional
class SubjectMappingTests @Autowired constructor(
    private val subjectRepository: SubjectRepository,
    private val userRepository: UserRepository,
    private val entityManager: EntityManager,
    private val jdbc: JdbcTemplate,
) {
    @Test
    fun `사용자는 subject 와 user 테이블에 나뉘어 저장되고 Subject 로 조회해도 User 로 복원된다`() {
        val user = userRepository.save(User(empNo = "E-001", name = "홍길동", hireDate = LocalDate.of(2024, 3, 1)))
        entityManager.flush()
        entityManager.clear()

        val found = subjectRepository.findById(user.requireId()).orElseThrow()

        assertIs<User>(found)
        assertEquals(SubjectType.USER, found.subjectType)
        assertEquals(SubjectStatus.ACTIVE, found.status)
        assertEquals("홍길동", found.subjectName)
        assertEquals(LocalDate.of(2024, 3, 1), found.hireDate)
        assertNotNull(found.createdAt)
        assertEquals("USER", subjectTypeColumn(user.requireId()))
        assertEquals(user.requireId(), userRepository.findByEmpNo("E-001")?.requireId())
    }

    @Test
    fun `서비스 계정과 AI 에이전트는 소유자 subject 를 ID 로 참조한다`() {
        val owner = userRepository.save(User(empNo = "E-002", name = "소유자"))
        val service = subjectRepository.save(ServiceAccount("batch-sync", owner.requireId(), Environment.PROD))
        val agent = subjectRepository.save(AiAgent("요약 봇", owner.requireId(), RiskLevel.HIGH, modelName = "claude"))
        entityManager.flush()
        entityManager.clear()

        assertEquals("SERVICE", subjectTypeColumn(service.requireId()))
        assertEquals("AI_AGENT", subjectTypeColumn(agent.requireId()))
        val foundAgent = assertIs<AiAgent>(subjectRepository.findById(agent.requireId()).orElseThrow())
        assertEquals(owner.requireId(), foundAgent.ownerSubjectId)
        assertEquals(RiskLevel.HIGH, foundAgent.riskLevel)
    }

    private fun subjectTypeColumn(subjectId: Long): String? =
        jdbc.queryForObject("SELECT subject_type FROM subject WHERE subject_id = ?", String::class.java, subjectId)
}
