package com.didrakon.iam.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import java.time.Clock
import java.time.ZoneId

@Configuration
class TimeConfig {
    /** 현재 시각은 이 Clock 으로만 얻는다. 테스트에서 시각을 고정할 수 있다 */
    @Bean
    fun clock(): Clock = Clock.system(ZoneId.of("Asia/Seoul"))
}
