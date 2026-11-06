package com.didrakon.iam.config

import com.didrakon.iam.authn.config.AuthnProperties
import com.didrakon.iam.authn.config.AuthorizationServerConfig
import com.didrakon.iam.authz.IntegrationTest
import net.javacrumbs.shedlock.core.LockConfiguration
import net.javacrumbs.shedlock.core.LockProvider
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import org.springframework.beans.factory.annotation.Autowired
import java.time.Duration
import java.time.Instant
import kotlin.test.assertFalse
import kotlin.test.assertTrue

@IntegrationTest
class SecurityHardeningTests @Autowired constructor(
    private val lockProvider: LockProvider,
) {
    @Test
    fun `분산 락은 같은 작업을 동시에 한 곳에서만 잡고 풀면 다시 잡을 수 있다`() {
        val config = LockConfiguration(Instant.now(), "test-${System.nanoTime()}", Duration.ofMinutes(1), Duration.ZERO)

        val first = lockProvider.lock(config)
        assertTrue(first.isPresent)
        assertFalse(lockProvider.lock(config).isPresent)

        first.get().unlock()
        assertTrue(lockProvider.lock(config).isPresent)
    }

    @Test
    fun `고정 서명 키를 요구하는 설정에서 키가 없으면 기동하지 않는다`() {
        val config = AuthorizationServerConfig(AuthnProperties(requirePersistentJwtKey = true))

        assertThrows<IllegalStateException> { config.rsaKey() }
    }
}
