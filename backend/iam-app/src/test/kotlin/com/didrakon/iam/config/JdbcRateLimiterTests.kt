package com.didrakon.iam.config

import com.didrakon.iam.authz.AuthzTest
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.jdbc.core.JdbcTemplate
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** 여러 서버가 DB 카운터를 함께 쓴다. 테스트마다 롤백된다 */
@AuthzTest
class JdbcRateLimiterTests @Autowired constructor(private val jdbc: JdbcTemplate) {
    private val clock = Clock.fixed(Instant.parse("2026-11-04T00:00:10Z"), ZoneId.of("Asia/Seoul"))

    @Test
    fun `두 서버가 같은 키를 함께 세서 합이 한도를 넘으면 막는다`() {
        val serverA = JdbcRateLimiter(jdbc, clock)
        val serverB = JdbcRateLimiter(jdbc, clock)
        val key = "login:10.0.0.${System.nanoTime() % 200}"

        assertTrue(serverA.tryAcquire(key, 3).first)
        assertTrue(serverB.tryAcquire(key, 3).first)
        assertTrue(serverA.tryAcquire(key, 3).first)
        val (allowed, retryAfter) = serverB.tryAcquire(key, 3)

        assertFalse(allowed)
        assertEquals(50, retryAfter)
    }

    @Test
    fun `지난 구간 카운터는 정리된다`() {
        val key = "token:10.0.1.${System.nanoTime() % 200}"
        JdbcRateLimiter(jdbc, Clock.fixed(Instant.parse("2026-11-04T00:00:10Z").minusSeconds(600), ZoneId.of("Asia/Seoul"))).tryAcquire(key, 5)

        JdbcRateLimiter(jdbc, clock).cleanup()

        assertEquals(0, jdbc.queryForObject("SELECT COUNT(*) FROM rate_limit_counter WHERE counter_key = ?", Int::class.java, key))
    }
}
