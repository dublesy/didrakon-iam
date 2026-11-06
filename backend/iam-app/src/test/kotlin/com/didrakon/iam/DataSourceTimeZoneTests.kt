package com.didrakon.iam

import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.context.annotation.Import
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.test.context.ActiveProfiles
import kotlin.test.assertContains

/** 서버·JVM 시간대와 무관하게 DB 세션이 KST 로 고정되는지 확인한다 */
@SpringBootTest
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class)
class DataSourceTimeZoneTests @Autowired constructor(
    private val jdbcTemplate: JdbcTemplate,
) {
    @Test
    fun `DB 세션 시간대는 KST 로 고정된다`() {
        val sessionTimeZone = jdbcTemplate.queryForObject("SELECT @@session.time_zone", String::class.java)

        assertContains(setOf("Asia/Seoul", "+09:00"), sessionTimeZone)
    }
}
