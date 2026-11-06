package com.didrakon.iam

import com.didrakon.iam.common.crypto.randomBytes
import org.springframework.boot.test.context.TestConfiguration
import org.springframework.boot.testcontainers.service.connection.ServiceConnection
import org.springframework.boot.web.servlet.FilterRegistrationBean
import org.springframework.core.Ordered
import org.springframework.session.SessionRepository
import org.springframework.context.annotation.Bean
import org.springframework.test.context.DynamicPropertyRegistrar
import org.testcontainers.mysql.MySQLContainer
import org.testcontainers.utility.DockerImageName
import java.util.Base64

@TestConfiguration(proxyBeanMethods = false)
class TestcontainersConfiguration {
    @Bean
    @ServiceConnection
    fun mysqlContainer(): MySQLContainer = MySQLContainer(DockerImageName.parse("mysql:8.4"))

    /** MockMvc 요청도 실제 세션 저장소(DB)를 거치게 한다. Spring Session 필터보다 앞에 둔다 */
    @Bean
    fun jdbcSessionMockMvcBridge(sessions: SessionRepository<*>): FilterRegistrationBean<JdbcSessionMockMvcBridge> =
        FilterRegistrationBean(JdbcSessionMockMvcBridge(sessions)).apply { order = Ordered.HIGHEST_PRECEDENCE }

    /** 비밀값 암호화 키는 저장소에 두지 않고 테스트 실행마다 새로 만든다 */
    @Bean
    fun testSecrets(): DynamicPropertyRegistrar = DynamicPropertyRegistrar { registry ->
        registry.add("iam.authn.secret-key") { Base64.getEncoder().encodeToString(randomBytes(32)) }
        // 만료 스케줄러가 테스트 데이터를 건드리지 않도록 끈다 (만료 처리는 테스트가 직접 호출한다)
        registry.add("iam.scheduling.enabled") { "false" }
    }
}
