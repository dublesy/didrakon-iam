package com.didrakon.iam.webhook

import com.didrakon.iam.authn.mfa.SecretStore
import net.javacrumbs.shedlock.spring.annotation.SchedulerLock
import org.slf4j.LoggerFactory
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty
import org.springframework.scheduling.annotation.EnableScheduling
import org.springframework.scheduling.annotation.Scheduled
import org.springframework.stereotype.Component
import org.apache.hc.client5.http.DnsResolver
import org.apache.hc.client5.http.classic.methods.HttpPost
import org.apache.hc.client5.http.config.ConnectionConfig
import org.apache.hc.client5.http.config.RequestConfig
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient
import org.apache.hc.client5.http.impl.classic.HttpClients
import org.apache.hc.client5.http.impl.io.PoolingHttpClientConnectionManagerBuilder
import org.apache.hc.core5.http.ContentType
import org.apache.hc.core5.http.io.entity.StringEntity
import org.apache.hc.core5.util.Timeout
import org.springframework.beans.factory.DisposableBean
import java.net.InetAddress
import java.time.Clock
import java.time.Duration
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/** 서명: `sha256=` + hex(HMAC-SHA256(비밀값, 타임스탬프 + "." + 본문)) */
object WebhookSignature {
    fun sign(secret: ByteArray, timestamp: Long, body: String): String {
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(secret, "HmacSHA256")) }
        return "sha256=" + mac.doFinal("$timestamp.$body".toByteArray()).joinToString("") { "%02x".format(it) }
    }
}

/**
 * 웹훅 전송용 HTTP 클라이언트. DNS 해석을 [WebhookAddressGuard] 가 맡아 내부망 주소로는 접속하지 않는다.
 * 리다이렉트·자동 재시도·시스템 프록시는 쓰지 않는다 (재시도는 전달 작업이 정한다)
 */
object WebhookHttpClient {
    fun create(guard: WebhookAddressGuard, timeout: Duration): CloseableHttpClient {
        val dns = object : DnsResolver {
            override fun resolve(host: String): Array<InetAddress> = guard.resolve(host)
            override fun resolveCanonicalHostname(host: String): String = host
        }
        val connections = PoolingHttpClientConnectionManagerBuilder.create()
            .setDnsResolver(dns)
            .setDefaultConnectionConfig(
                ConnectionConfig.custom().setConnectTimeout(Timeout.of(timeout)).setSocketTimeout(Timeout.of(timeout)).build(),
            )
            .build()
        return HttpClients.custom()
            .setConnectionManager(connections)
            .setDefaultRequestConfig(RequestConfig.custom().setResponseTimeout(Timeout.of(timeout)).setRedirectsEnabled(false).build())
            .disableRedirectHandling()
            .disableAutomaticRetries()
            .disableCookieManagement()
            .build()
    }
}

/**
 * 커밋된 전달(PENDING·FAILED 중 차례가 된 것)을 보낸다. 구독마다 만든 순서(전달 ID 순)대로 보낸다:
 * 앞 전달이 성공하거나 포기(DEAD)될 때까지 뒤 전달은 기다린다. 접속할 주소는 [WebhookHttpClient] 의 DNS 해석에서 내부망인지 확인한다. 2xx 면 성공, 아니면 [RETRY_DELAYS] 간격으로 다시 보내고
 * [MAX_ATTEMPTS] 번 실패하면 DEAD 로 둔다. 같은 전달이 두 번 갈 수 있으므로(최소 한 번) 받는 쪽은 전달 ID 로 중복을 거른다.
 * HTTP 호출은 트랜잭션 밖에서 하고, 결과는 전달마다 따로 저장한다.
 */
@Component
class WebhookDispatcher(
    private val repository: WebhookRepository,
    private val secretStore: SecretStore,
    addressGuard: WebhookAddressGuard,
    private val clock: Clock,
) : DisposableBean {
    private val log = LoggerFactory.getLogger(javaClass)
    private val httpClient: CloseableHttpClient = WebhookHttpClient.create(addressGuard, TIMEOUT)

    override fun destroy() = httpClient.close()

    /** 차례가 된 전달을 최대 [limit] 건 보낸다. 보낸 건수를 돌려준다 */
    fun dispatchDue(limit: Int = BATCH_SIZE): Int {
        val secrets = HashMap<String, ByteArray>()
        var sent = 0
        // 한 번에 구독마다 맨 앞 전달만 차례가 된다. 성공하면 다음 전달이 맨 앞이 되므로 남은 한도 안에서 다시 고른다
        while (sent < limit) {
            val due = repository.due(clock.instant(), limit - sent)
            if (due.isEmpty()) break
            due.forEach { deliver(it, secrets) }
            sent += due.size
        }
        return sent
    }

    private fun deliver(delivery: DueDelivery, secrets: MutableMap<String, ByteArray>) {
        val attempts = delivery.attempts + 1
        val (statusCode, error) = try {
            val secret = secrets.getOrPut(delivery.secretReference) { secretStore.load(delivery.secretReference) }
            val code = send(delivery, secret)
            code to (if (code in 200..299) null else "HTTP $code")
        } catch (e: Exception) {
            null to e.javaClass.simpleName
        }
        val now = clock.instant()
        if (error == null && statusCode != null) {
            repository.markSucceeded(delivery.deliveryId, attempts, statusCode, now)
            return
        }
        val failure = error ?: "UNKNOWN"
        if (attempts >= MAX_ATTEMPTS) {
            repository.markFailed(delivery.deliveryId, DeliveryStatus.DEAD, attempts, now, statusCode, failure)
            log.warn("웹훅 전달 포기: delivery={}, type={}, attempts={}, error={}", delivery.deliveryId, delivery.eventType, attempts, failure)
        } else {
            repository.markFailed(delivery.deliveryId, DeliveryStatus.FAILED, attempts, now.plus(RETRY_DELAYS[attempts - 1]), statusCode, failure)
            log.info("웹훅 전달 실패: delivery={}, type={}, attempts={}, error={}", delivery.deliveryId, delivery.eventType, attempts, failure)
        }
    }

    private fun send(delivery: DueDelivery, secret: ByteArray): Int {
        val timestamp = clock.instant().epochSecond
        val request = HttpPost(delivery.url).apply {
            entity = StringEntity(delivery.payload, ContentType.APPLICATION_JSON)
            addHeader("X-Didrakon-Event", delivery.eventType)
            addHeader("X-Didrakon-Delivery", delivery.deliveryId.toString())
            addHeader("X-Didrakon-Timestamp", timestamp.toString())
            addHeader("X-Didrakon-Signature", WebhookSignature.sign(secret, timestamp, delivery.payload))
        }
        // 응답 본문은 읽지 않고 버린다 (핸들러가 끝나면 연결을 돌려준다)
        return httpClient.execute(request) { it.code }
    }

    companion object {
        const val BATCH_SIZE = 100
        const val MAX_ATTEMPTS = 6
        private val TIMEOUT: Duration = Duration.ofSeconds(5)

        /** n 번째 실패 뒤 다음 시도까지 (n = 1..5). 6 번째 실패면 DEAD */
        val RETRY_DELAYS: List<Duration> = listOf(
            Duration.ofSeconds(30), Duration.ofMinutes(2), Duration.ofMinutes(10), Duration.ofHours(1), Duration.ofHours(6),
        )
    }
}

/** 전달 작업 주기 실행. 만료 스케줄러와 같은 조건(iam.scheduling.enabled)·분산 락을 쓰고, 락 이름은 따로 둔다 */
@Component
@EnableScheduling
@ConditionalOnProperty("iam.scheduling.enabled", havingValue = "true", matchIfMissing = true)
class WebhookScheduler(
    private val dispatcher: WebhookDispatcher,
    private val repository: WebhookRepository,
    private val clock: java.time.Clock,
    @org.springframework.beans.factory.annotation.Value("\${iam.webhook.retention:P30D}") private val retention: java.time.Duration,
) {
    @Scheduled(fixedDelayString = "\${iam.webhook.interval:PT10S}", initialDelayString = "\${iam.webhook.interval:PT10S}")
    @SchedulerLock(name = "iam-webhook", lockAtMostFor = "PT20M")
    fun dispatch() {
        dispatcher.dispatchDue()
    }

    /** 끝난 전달 기록은 보관 기간(iam.webhook.retention, 기본 30일)이 지나면 지운다. 하루 한 번 */
    @Scheduled(cron = "0 30 3 * * *")
    @SchedulerLock(name = "iam-webhook-purge", lockAtMostFor = "PT30M")
    fun purge() {
        repository.purgeFinished(clock.instant().minus(retention))
    }
}
