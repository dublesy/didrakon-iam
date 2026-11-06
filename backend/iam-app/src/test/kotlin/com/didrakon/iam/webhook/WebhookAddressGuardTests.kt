package com.didrakon.iam.webhook

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertDoesNotThrow
import org.junit.jupiter.api.assertThrows
import org.apache.hc.client5.http.classic.methods.HttpPost
import java.net.InetAddress
import java.time.Duration
import kotlin.test.assertEquals

/** 내부망 차단 (SSRF). 운영 기본값(allow-private-network=false)으로 검사한다 */
class WebhookAddressGuardTests {
    private val guard = WebhookAddressGuard(allowPrivateNetwork = false)

    @Test
    fun `루프백·사설·링크 로컬·CGNAT·IPv6 내부 주소는 막는다`() {
        listOf(
            "http://127.0.0.1/hook", "http://localhost:8080/hook", "http://10.1.2.3/", "http://172.16.0.1/",
            "http://192.168.0.10/", "http://169.254.169.254/latest/meta-data", "http://100.64.0.1/", "http://0.0.0.0/",
            "http://[::1]/", "http://[fd00::1]/", "http://[fe80::1]/", "http://[::ffff:127.0.0.1]/",
        ).forEach { url -> assertThrows<BlockedAddressException>(url) { guard.check(url) } }
    }

    @Test
    fun `공인 주소는 통과한다`() {
        listOf("https://93.184.216.34/hook", "https://[2606:4700:4700::1111]/hook").forEach { url ->
            assertDoesNotThrow(url) { guard.check(url) }
        }
    }

    @Test
    fun `허용 설정이면 내부망도 통과한다`() {
        assertDoesNotThrow { WebhookAddressGuard(allowPrivateNetwork = true).check("http://127.0.0.1/hook") }
    }

    @Test
    fun `전송 클라이언트는 접속할 때 해석한 주소로 내부망을 막고, 허용 설정이면 보낸다`() {
        Receiver(204).use { receiver ->
            WebhookHttpClient.create(guard, Duration.ofSeconds(2)).use { client ->
                assertThrows<BlockedAddressException> { client.execute(HttpPost(receiver.url)) { it.code } }
            }
            assertEquals(0, receiver.received.size, "막힌 요청은 받는 쪽에 닿지 않는다")
            WebhookHttpClient.create(WebhookAddressGuard(allowPrivateNetwork = true), Duration.ofSeconds(2)).use { client ->
                assertEquals(204, client.execute(HttpPost(receiver.url)) { it.code })
            }
        }
    }

    @Test
    fun `사설 대역 판정`() {
        assertThrows<BlockedAddressException> { guard.check("http://198.18.0.1/") }
        assert(!WebhookAddressGuard.isPrivate(InetAddress.getByName("8.8.8.8")))
    }
}
