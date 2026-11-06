package com.didrakon.iam.config

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.beans.factory.ObjectProvider
import org.springframework.jdbc.core.ConnectionCallback
import org.springframework.jdbc.core.JdbcTemplate
import jakarta.servlet.FilterChain
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.web.filter.OncePerRequestFilter
import java.time.Clock
import java.time.Duration
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicInteger

/**
 * IP 별 호출 수 제한 (1분 고정 구간). 로그인 무차별 대입과 API 과호출을 막는다.
 * 기본은 서버마다 따로 센다. 여러 대로 운영하면 `store: jdbc` 로 로그인·토큰 경로를 DB 에서 함께 센다
 * (그 경로는 서버를 늘려도 한도가 늘면 안 된다). 권한 판정·관리 API 는 호출이 많아 서버별로 센다.
 * 클라이언트 IP 는 request.remoteAddr 다. 운영에서는 프록시 뒤 실제 IP 가 들어오도록 forward-headers 를 켠다 (application-prod.yml)
 */
@ConfigurationProperties("iam.rate-limit")
data class RateLimitProperties(
    val enabled: Boolean = true,
    /** 로그인·MFA·비밀번호 변경·셀프 재설정 POST */
    val loginPerMinute: Int = 20,
    /** OAuth2 토큰 발급·갱신 */
    val tokenPerMinute: Int = 120,
    /** 다른 시스템의 권한 판정 호출 (서버 몇 대에서 몰려 오므로 크게 둔다) */
    val authzCheckPerMinute: Int = 6000,
    /** 그 밖의 관리·본인 API */
    val apiPerMinute: Int = 600,
    /** memory: 서버별. jdbc: 로그인·토큰 경로를 DB 에서 여러 서버가 함께 센다 */
    val store: String = "memory",
)

/** 키별 1분 고정 구간 카운터. 한도 안이면 true 와 함께, 이번 구간이 끝날 때까지 남은 초 */
interface RateLimiter {
    fun tryAcquire(key: String, limit: Int): Pair<Boolean, Long>
}

/** 서버 메모리 카운터. 오래된 구간은 다음 구간이 시작될 때 지운다 */
class FixedWindowRateLimiter(private val clock: Clock, private val window: Duration = Duration.ofMinutes(1)) : RateLimiter {
    private val counters = ConcurrentHashMap<String, AtomicInteger>()

    @Volatile
    private var currentWindow = windowOf()

    override fun tryAcquire(key: String, limit: Int): Pair<Boolean, Long> {
        val window = windowOf()
        if (window != currentWindow) {
            synchronized(this) {
                if (window != currentWindow) {
                    counters.clear()
                    currentWindow = window
                }
            }
        }
        val count = counters.computeIfAbsent(key) { AtomicInteger() }.incrementAndGet()
        val retryAfter = (window + 1) * this.window.seconds - clock.instant().epochSecond
        return (count <= limit) to retryAfter
    }

    private fun windowOf(): Long = clock.instant().epochSecond / window.seconds
}

/**
 * DB 카운터. 같은 (키, 구간) 행을 원자적으로 1 올리고 그 값을 읽는다 (INSERT … ON DUPLICATE KEY UPDATE + LAST_INSERT_ID,
 * 같은 연결에서). 지난 구간은 [cleanup] 이 지운다
 */
class JdbcRateLimiter(
    private val jdbcTemplate: JdbcTemplate,
    private val clock: Clock,
    private val window: Duration = Duration.ofMinutes(1),
) : RateLimiter {
    override fun tryAcquire(key: String, limit: Int): Pair<Boolean, Long> {
        val now = clock.instant().epochSecond
        val windowStart = now / window.seconds * window.seconds
        val count = jdbcTemplate.execute(ConnectionCallback { connection ->
            connection.prepareStatement(
                """
                INSERT INTO rate_limit_counter (counter_key, window_start, hit_count) VALUES (?, ?, LAST_INSERT_ID(1))
                ON DUPLICATE KEY UPDATE hit_count = LAST_INSERT_ID(hit_count + 1)
                """,
            ).use { it.setString(1, key.take(200)); it.setLong(2, windowStart); it.executeUpdate() }
            connection.createStatement().use { st -> st.executeQuery("SELECT LAST_INSERT_ID()").use { rs -> rs.next(); rs.getLong(1) } }
        }) ?: 0L
        return (count <= limit) to (windowStart + window.seconds - now)
    }

    /** 지난 구간 행을 지운다. 지운 행 수 */
    fun cleanup(): Int = jdbcTemplate.update("DELETE FROM rate_limit_counter WHERE window_start < ?", clock.instant().epochSecond - window.seconds * 2)
}

class RateLimitFilter(
    private val properties: RateLimitProperties,
    private val limiter: RateLimiter,
    /** 로그인·토큰 경로에 쓸 카운터. 여러 서버가 함께 세려면 [JdbcRateLimiter] */
    private val securityLimiter: RateLimiter = limiter,
) : OncePerRequestFilter() {
    override fun doFilterInternal(request: HttpServletRequest, response: HttpServletResponse, filterChain: FilterChain) {
        val rule = ruleOf(request)
        if (rule == null) {
            filterChain.doFilter(request, response)
            return
        }
        val (name, limit) = rule
        val counter = if (name == "login" || name == "token") securityLimiter else limiter
        val (allowed, retryAfter) = counter.tryAcquire("$name:${request.remoteAddr}", limit)
        if (allowed) {
            filterChain.doFilter(request, response)
            return
        }
        response.status = 429
        response.setHeader("Retry-After", retryAfter.toString())
        response.characterEncoding = "UTF-8"
        if (name == "login") {
            response.contentType = "text/plain;charset=UTF-8"
            response.writer.write("요청이 너무 많습니다. ${retryAfter}초 뒤 다시 시도하세요")
        } else {
            response.contentType = "application/json"
            response.writer.write("""{"success":false,"data":null,"error":{"code":"TOO_MANY_REQUESTS","message":"요청이 너무 많습니다. ${retryAfter}초 뒤 다시 시도하세요"}}""")
        }
    }

    private fun ruleOf(request: HttpServletRequest): Pair<String, Int>? {
        val path = request.requestURI.removePrefix(request.contextPath)
        return when {
            request.method == "POST" && path in LOGIN_PATHS -> "login" to properties.loginPerMinute
            path == "/oauth2/token" -> "token" to properties.tokenPerMinute
            path == "/api/v1/authz/check" -> "check" to properties.authzCheckPerMinute
            path.startsWith("/api/") -> "api" to properties.apiPerMinute
            else -> null
        }
    }

    companion object {
        private val LOGIN_PATHS = setOf("/login", "/login/mfa", "/login/password", "/login/forgot")
    }
}

@Configuration
@EnableConfigurationProperties(RateLimitProperties::class)
class RateLimitConfig {
    @Bean
    @ConditionalOnProperty("iam.rate-limit.store", havingValue = "jdbc")
    fun jdbcRateLimiter(jdbcTemplate: JdbcTemplate, clock: Clock) = JdbcRateLimiter(jdbcTemplate, clock)

    /** 보안 필터보다 먼저 세어, 인증을 시도하기 전에 막는다 */
    @Bean
    fun rateLimitFilter(properties: RateLimitProperties, clock: Clock, jdbcLimiter: ObjectProvider<JdbcRateLimiter>): FilterRegistrationBean<RateLimitFilter> {
        val memory = FixedWindowRateLimiter(clock)
        return FilterRegistrationBean(RateLimitFilter(properties, memory, jdbcLimiter.ifAvailable ?: memory)).apply {
            order = Ordered.HIGHEST_PRECEDENCE + 10
            isEnabled = properties.enabled
        }
    }
}
