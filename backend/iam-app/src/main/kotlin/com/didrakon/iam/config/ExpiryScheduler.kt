package com.didrakon.iam.config

import org.springframework.beans.factory.ObjectProvider
import com.didrakon.iam.authz.assignment.RoleAssignmentService
import com.didrakon.iam.governance.breakglass.BreakGlassService
import com.didrakon.iam.governance.delegation.DelegationService
import com.didrakon.iam.governance.request.AccessRequestService
import com.didrakon.iam.governance.review.AccessReviewService
import com.didrakon.iam.identity.subject.UserService
import net.javacrumbs.shedlock.core.LockProvider
import net.javacrumbs.shedlock.provider.jdbctemplate.JdbcTemplateLockProvider
import net.javacrumbs.shedlock.spring.annotation.EnableSchedulerLock
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component

/** 스케줄 작업 분산 락. 여러 인스턴스 중 락을 잡은 한 곳에서만 실행된다 (shedlock 테이블, DB 시각 기준) */
@Configuration
@EnableSchedulerLock(defaultLockAtMostFor = "PT10M")
class SchedulerLockConfig {
    @Bean
    fun lockProvider(jdbcTemplate: JdbcTemplate): LockProvider = JdbcTemplateLockProvider(
        JdbcTemplateLockProvider.Configuration.builder().withJdbcTemplate(jdbcTemplate).usingDbTime().build(),
    )
}

/**
 * 기간이 끝난 할당·요청·위임·비상 접근의 상태를 맞추고, 퇴사 예정일이 된 사용자를 퇴사 처리하고, 기한이 지난 접근 재검토를 닫는다. 판정은 유효 기간으로 이미 걸러내므로 상태·이력 정리 작업이다.
 * 각 작업은 여러 번 실행해도 결과가 같고, 분산 락으로 동시에 한 인스턴스에서만 돈다.
 */
@Component
@EnableScheduling
@ConditionalOnProperty("iam.scheduling.enabled", havingValue = "true", matchIfMissing = true)
class ExpiryScheduler(
    private val assignmentService: RoleAssignmentService,
    private val accessRequestService: AccessRequestService,
    private val delegationService: DelegationService,
    private val breakGlassService: BreakGlassService,
    private val accessReviewService: AccessReviewService,
    private val userService: UserService,
    private val rateLimiter: ObjectProvider<JdbcRateLimiter>,
) {
    private val log = LoggerFactory.getLogger(javaClass)

    @Scheduled(fixedDelayString = "\${iam.scheduling.expiry-interval:PT1M}")
    @SchedulerLock(name = "iam-expiry", lockAtMostFor = "PT5M", lockAtLeastFor = "PT30S")
    fun expire() {
        val assignments = assignmentService.expireDue()
        val requests = accessRequestService.expirePending()
        val delegations = delegationService.refreshStatuses()
        val breakGlass = breakGlassService.expireDue()
        val retired = userService.retireDue()
        val reviews = accessReviewService.closeOverdue()
        rateLimiter.ifAvailable?.cleanup()
        if (assignments + requests + delegations + breakGlass + retired + reviews > 0) {
            log.info(
                "만료 처리: 할당 {}, 요청 {}, 위임 {}, 비상 접근 {}, 예약 퇴사 {}, 기한 지난 접근 재검토 {}",
                assignments, requests, delegations, breakGlass, retired, reviews,
            )
        }
    }
}
