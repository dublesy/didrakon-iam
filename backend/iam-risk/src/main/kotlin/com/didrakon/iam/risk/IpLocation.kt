package com.didrakon.iam.risk

import com.maxmind.geoip2.DatabaseReader
import org.slf4j.LoggerFactory
import org.springframework.boot.context.properties.ConfigurationProperties
import org.springframework.boot.context.properties.EnableConfigurationProperties
import org.springframework.boot.context.properties.bind.Bindable
import org.springframework.boot.context.properties.bind.Binder
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Condition
import org.springframework.context.annotation.ConditionContext
import org.springframework.context.annotation.Conditional
import org.springframework.context.annotation.Configuration
import org.springframework.core.type.AnnotatedTypeMetadata
import java.io.File
import java.net.Inet6Address
import java.net.InetAddress

/** 위험 평가 설정. application.yml 의 iam.risk.* */
@ConfigurationProperties("iam.risk")
data class RiskProperties(
    /**
     * 로그인 위험 조치가 CHALLENGE·APPROVAL 인데 확인된 MFA 수단이 없으면 로그인을 막는다.
     * false 면 예전처럼 기록만 하고 들여보낸다
     */
    val blockChallengeWithoutMfa: Boolean = true,
    /** MaxMind GeoLite2/GeoIP2 Country 파일(.mmdb) 경로. 넣으면 FOREIGN_IP 가 이 파일로 국가를 찾는다 */
    val geoipDatabase: String? = null,
    /** CIDR → 국가 코드 (예: 사무실 대역). DB 보다 먼저 본다. DB 없이 이것만 써도 된다 */
    val ipCountryOverrides: Map<String, String> = emptyMap(),
)

/**
 * 설정한 CIDR 대역 → GeoIP DB 순으로 국가를 찾는다. 사설·루프백·링크 로컬 주소는 DB 에서 찾지 않는다(모름).
 * 찾다가 실패하면 모름(null)으로 두고 로그인을 막지 않는다
 */
class ConfiguredIpLocationResolver(
    overrides: Map<String, String>,
    databaseFile: File?,
) : IpLocationResolver, AutoCloseable {
    private val log = LoggerFactory.getLogger(javaClass)
    private val ranges = overrides.map { (cidr, country) -> Cidr.parse(cidr) to country.trim().uppercase() }

    /** 파일이 없거나 읽을 수 없으면 기동하지 않는다 (조용히 꺼진 채 운영되지 않게) */
    private val database: DatabaseReader? = databaseFile?.let { DatabaseReader.Builder(it).build() }

    override fun countryOf(ipAddress: String): String? {
        val address = literal(ipAddress) ?: return null
        ranges.firstOrNull { it.first.contains(address) }?.let { return it.second }
        val reader = database ?: return null
        if (isLocal(address)) return null
        return runCatching { reader.tryCountry(address).map { it.country?.isoCode }.orElse(null) }
            .onFailure { log.debug("IP 국가를 찾지 못했습니다: {}", ipAddress, it) }
            .getOrNull()
    }

    override fun close() {
        database?.close()
    }

    private fun isLocal(address: InetAddress): Boolean =
        address.isLoopbackAddress || address.isSiteLocalAddress || address.isLinkLocalAddress || address.isAnyLocalAddress ||
            (address is Inet6Address && address.address[0].toInt() and 0xFE == 0xFC) // IPv6 고유 로컬 fc00::/7

    /** CIDR 한 대역. 접두 길이가 없으면 주소 하나 */
    class Cidr(private val network: ByteArray, private val prefix: Int) {
        fun contains(address: InetAddress): Boolean {
            val bytes = address.address
            if (bytes.size != network.size) return false
            val fullBytes = prefix / 8
            if ((0 until fullBytes).any { bytes[it] != network[it] }) return false
            val rest = prefix % 8
            if (rest == 0) return true
            val mask = (0xFF shl (8 - rest)) and 0xFF
            return (bytes[fullBytes].toInt() and mask) == (network[fullBytes].toInt() and mask)
        }

        companion object {
            /** 잘못된 값은 기동할 때 바로 드러나도록 예외를 낸다 */
            fun parse(value: String): Cidr {
                val (ip, length) = value.trim().split("/", limit = 2).let { it[0] to it.getOrNull(1) }
                val address = literal(ip) ?: throw IllegalArgumentException("iam.risk.ip-country-overrides 의 대역이 올바르지 않습니다: $value")
                val bits = address.address.size * 8
                val prefix = length?.toIntOrNull()?.takeIf { it in 0..bits }
                    ?: if (length == null) bits else throw IllegalArgumentException("iam.risk.ip-country-overrides 의 접두 길이가 올바르지 않습니다: $value")
                return Cidr(address.address, prefix)
            }
        }
    }

    companion object {
        /** IP 문자열만 주소로 바꾼다. 호스트 이름은 DNS 조회를 하게 되므로 받지 않는다 */
        fun literal(value: String): InetAddress? {
            if (value.isEmpty() || !value.all { it.isDigit() || it == '.' || it == ':' || it.lowercaseChar() in 'a'..'f' }) return null
            if (':' !in value && value.count { it == '.' } != 3) return null
            return runCatching { InetAddress.getByName(value) }.getOrNull()
        }
    }
}

/** IP 국가 판별은 GeoIP DB 경로나 CIDR 대역을 설정했을 때만 켠다. 둘 다 없으면 FOREIGN_IP 는 잡히지 않는다 */
@Configuration
@EnableConfigurationProperties(RiskProperties::class)
class RiskConfig {
    @Bean
    @Conditional(IpLocationConfigured::class)
    fun ipLocationResolver(properties: RiskProperties): ConfiguredIpLocationResolver =
        ConfiguredIpLocationResolver(
            properties.ipCountryOverrides,
            properties.geoipDatabase?.takeIf { it.isNotBlank() }?.let { File(it) },
        )

    class IpLocationConfigured : Condition {
        override fun matches(context: ConditionContext, metadata: AnnotatedTypeMetadata): Boolean {
            val binder = Binder.get(context.environment)
            val database = binder.bind("iam.risk.geoip-database", String::class.java).map { it.isNotBlank() }.orElse(false)
            val overrides = binder.bind("iam.risk.ip-country-overrides", Bindable.mapOf(String::class.java, String::class.java))
                .map { it.isNotEmpty() }.orElse(false)
            return database == true || overrides == true
        }
    }
}
