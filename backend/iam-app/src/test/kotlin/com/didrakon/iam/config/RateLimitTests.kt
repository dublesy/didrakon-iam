package com.didrakon.iam.config

import org.junit.jupiter.api.Test
import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import java.time.Clock
import java.time.Instant
import java.time.ZoneId
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RateLimitTests {
    /** 테스트가 시각을 옮길 수 있는 시계 */
    private class MovableClock(var now: Instant) : Clock() {
        override fun getZone(): ZoneId = ZoneId.of("Asia/Seoul")
        override fun withZone(zone: ZoneId): Clock = this
        override fun instant(): Instant = now
    }

    private val clock = MovableClock(Instant.parse("2026-11-04T00:00:10Z"))

    @Test
    fun `한도까지는 통과하고 넘으면 막으며 다음 1분 구간에 다시 열린다`() {
        val limiter = FixedWindowRateLimiter(clock)
        repeat(3) { assertTrue(limiter.tryAcquire("login:1.1.1.1", 3).first) }

        val (allowed, retryAfter) = limiter.tryAcquire("login:1.1.1.1", 3)
        assertFalse(allowed)
        assertEquals(50, retryAfter)
        assertTrue(limiter.tryAcquire("login:2.2.2.2", 3).first, "다른 IP 는 따로 센다")

        clock.now = clock.now.plusSeconds(60)
        assertTrue(limiter.tryAcquire("login:1.1.1.1", 3).first)
    }

    @Test
    fun `로그인 POST 가 한도를 넘으면 429 와 Retry-After 를 준다`() {
        val filter = RateLimitFilter(RateLimitProperties(loginPerMinute = 1), FixedWindowRateLimiter(clock))
        fun login() = MockHttpServletResponse().also {
            filter.doFilter(MockHttpServletRequest("POST", "/login").apply { remoteAddr = "3.3.3.3" }, it, MockFilterChain())
        }

        assertEquals(200, login().status)
        val blocked = login()
        assertEquals(429, blocked.status)
        assertEquals("50", blocked.getHeader("Retry-After"))

        // 로그인 화면(GET)과 정적 자원은 세지 않는다
        val page = MockHttpServletResponse()
        filter.doFilter(MockHttpServletRequest("GET", "/login").apply { remoteAddr = "3.3.3.3" }, page, MockFilterChain())
        assertEquals(200, page.status)
    }
}
