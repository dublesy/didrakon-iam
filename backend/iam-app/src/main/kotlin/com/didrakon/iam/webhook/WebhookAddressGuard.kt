package com.didrakon.iam.webhook

import org.springframework.beans.factory.annotation.Value
import org.springframework.stereotype.Component
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.URI
import java.net.UnknownHostException

/**
 * 웹훅 주소가 내부망을 가리킨다. 전달 기록의 오류 이름(BlockedAddressException)으로 남는다.
 * DNS 해석 단계에서 던지므로 해석 실패([UnknownHostException])의 한 종류로 둔다
 */
class BlockedAddressException(message: String) : UnknownHostException(message)

/**
 * SSRF 방어. 웹훅 주소가 내부망(루프백·사설·링크 로컬·CGNAT·멀티캐스트 등)으로 풀리면 막는다.
 * 등록할 때 한 번 확인하고, 보낼 때는 HTTP 클라이언트의 DNS 해석([resolve])에서 확인한 주소로만 접속한다.
 * 확인과 접속이 같은 해석 결과를 쓰므로 그 사이에 DNS 가 내부 주소로 바뀌어도(DNS rebinding) 우회할 수 없다.
 * 리다이렉트는 따라가지 않으므로 응답으로 내부망에 우회할 수 없다.
 * 내부망 수신처를 쓰려면 `iam.webhook.allow-private-network: true` (로컬·테스트용).
 */
@Component
class WebhookAddressGuard(
    @Value("\${iam.webhook.allow-private-network:false}") private val allowPrivateNetwork: Boolean,
) {
    /** 주소를 풀어 내부망이면 [BlockedAddressException]. 풀리지 않는 이름은 [UnknownHostException] */
    fun check(url: String) {
        resolve(URI(url).host?.removeSurrounding("[", "]") ?: throw BlockedAddressException("호스트가 없습니다"))
    }

    /** 이름을 풀어 주소를 돌려준다. 하나라도 내부망이면 [BlockedAddressException] (일부만 걸러 접속하지 않는다) */
    fun resolve(host: String): Array<InetAddress> {
        val addresses = InetAddress.getAllByName(host.removeSurrounding("[", "]"))
        if (!allowPrivateNetwork && addresses.any { isPrivate(it) }) throw BlockedAddressException("내부망 주소로는 보낼 수 없습니다: $host")
        return addresses
    }

    companion object {
        fun isPrivate(address: InetAddress): Boolean {
            if (address.isAnyLocalAddress || address.isLoopbackAddress || address.isLinkLocalAddress ||
                address.isSiteLocalAddress || address.isMulticastAddress
            ) return true
            val b = address.address.map { it.toInt() and 0xff }
            return when (address) {
                is Inet4Address -> b[0] == 0 || // 0.0.0.0/8
                    (b[0] == 100 && b[1] in 64..127) || // CGNAT 100.64.0.0/10
                    (b[0] == 198 && b[1] in 18..19) || // 벤치마크 198.18.0.0/15
                    b[0] >= 240 // 예약·브로드캐스트 240.0.0.0/4
                is Inet6Address -> (b[0] and 0xfe) == 0xfc // ULA fc00::/7
                else -> false
            }
        }
    }
}
