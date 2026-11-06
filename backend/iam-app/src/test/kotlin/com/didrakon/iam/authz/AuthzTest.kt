package com.didrakon.iam.authz

import com.didrakon.iam.TestcontainersConfiguration
import org.springframework.boot.test.context.SpringBootTest
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc
import org.springframework.context.annotation.Import
import org.springframework.test.context.ActiveProfiles
import org.springframework.transaction.annotation.Transactional

/**
 * 통합 테스트 공통 설정 (MySQL 컨테이너 + MockMvc). 커밋되는 데이터는 고유 코드로 만들어 테스트끼리 겹치지 않게 한다.
 * 같은 설정을 쓰는 테스트는 스프링 컨텍스트와 컨테이너를 공유한다.
 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
@Import(TestcontainersConfiguration::class, AuthzFixture::class)
annotation class IntegrationTest

/** [IntegrationTest] + 테스트마다 롤백 */
@Target(AnnotationTarget.CLASS)
@Retention(AnnotationRetention.RUNTIME)
@IntegrationTest
@Transactional
annotation class AuthzTest
