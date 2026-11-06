package com.didrakon.iam.identity

import com.didrakon.iam.TestcontainersConfiguration
import com.didrakon.iam.identity.group.GroupMember
import com.didrakon.iam.identity.group.GroupMemberRepository
import com.didrakon.iam.identity.group.GroupMemberSourceType
import com.didrakon.iam.identity.group.GroupType
import com.didrakon.iam.identity.group.UserGroup
import com.didrakon.iam.identity.group.UserGroupRepository
import com.didrakon.iam.identity.subject.User
import com.didrakon.iam.identity.subject.UserRepository
import jakarta.persistence.EntityManager
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional
import java.time.Instant
import kotlin.test.assertEquals

/** JSON 규칙 컬럼과 복합 키(group_id, subject_id) 매핑을 확인한다 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
@Transactional
class GroupMappingTests @Autowired constructor(
    private val groupRepository: UserGroupRepository,
    private val memberRepository: GroupMemberRepository,
    private val userRepository: UserRepository,
    private val entityManager: EntityManager,
) {
    @Test
    fun `그룹 규칙은 JSON 으로 저장되고 구성원은 복합 키로 조회된다`() {
        val rule = """{"orgType": "CENTER"}"""
        val group = groupRepository.save(UserGroup("CENTER-LEADS", "센터장", GroupType.DYNAMIC, rule))
        val user = userRepository.save(User(empNo = "E-100", name = "센터장"))
        memberRepository.save(GroupMember(group.requireId(), user.requireId(), GroupMemberSourceType.RULE, Instant.now()))
        entityManager.flush()
        entityManager.clear()

        val found = groupRepository.findByGroupCode("CENTER-LEADS")
        val members = memberRepository.findByIdSubjectId(user.requireId())

        assertEquals(rule, found?.ruleExpression)
        assertEquals(listOf(group.requireId()), members.map { it.id.groupId })
    }
}
