package com.didrakon.iam.authn.token

import com.didrakon.iam.authn.client.SsoClientRepository
import com.didrakon.iam.authn.config.AuthnProperties
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.slf4j.LoggerFactory
import org.springframework.jdbc.core.JdbcTemplate
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.JwsHeader
import org.springframework.security.oauth2.jwt.JwtClaimsSet
import org.springframework.security.oauth2.jwt.JwtEncoderParameters
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder
import org.springframework.stereotype.Component
import org.springframework.transaction.event.TransactionPhase
import org.springframework.transaction.event.TransactionalEventListener
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Clock
import java.time.Duration
import java.util.UUID
import java.util.concurrent.Executors

/**
 * 로그아웃 토큰을 보낼 곳 하나: 연동 시스템(client_id)과 그 시스템에서 로그인했던 사용자.
 * [sid] 가 있으면 그 로그인 세션 하나만 끝난 것이고, 없으면 그 사용자의 모든 세션이 끝난 것이다
 */
data class LogoutTarget(val clientId: String, val logoutUri: String, val subjectId: String, val sid: String? = null)


/** 세션·토큰을 회수한 트랜잭션이 커밋된 뒤 보낸다 */
data class BackChannelLogoutEvent(val targets: List<LogoutTarget>)

/**
 * OIDC Back-Channel Logout 1.0. 로그인 세션이 끝나면 그 세션(또는 그 사용자)에게 토큰을 받은 연동 시스템 중
 * 수신 주소를 등록한 곳에 서명한 로그아웃 토큰(logout_token)을 POST 한다.
 *
 * - 대상은 토큰을 지우기 전에 [targetsBySession]·[targetsBySubject] 로 모은다
 * - 전송은 커밋 뒤 별도 스레드에서 한다. 연동 시스템이 느리거나 꺼져 있어도 IAM 요청을 막지 않고, 실패는 로그로만 남긴다
 * - 로그인 세션 하나가 끝나면(로그아웃·관리자 세션 종료) sub 와 함께 그 클라이언트에 준 ID 토큰의 sid 를 넣는다: 받는 쪽은 그 세션만 끝낸다.
 *   sid 는 Spring Authorization Server 가 ID 토큰에 넣은 값(로그인한 HTTP 세션 ID 의 해시)이며, 저장된 ID 토큰 claim 에서 읽는다.
 *   사용자 단위로 끝나면(사용 중지·잠금·퇴사) sid 없이 sub 만 넣는다: 받는 쪽은 그 사용자의 세션을 모두 끝낸다
 */
@Component
class BackChannelLogoutNotifier(
    private val jdbcTemplate: JdbcTemplate,
    private val ssoClientRepository: SsoClientRepository,
    jwkSource: JWKSource<SecurityContext>,
    private val properties: AuthnProperties,
    private val clock: Clock,
) {
    private val log = LoggerFactory.getLogger(javaClass)
    private val encoder = NimbusJwtEncoder(jwkSource)
    // HTTP/1.1 로 고정한다. 기본(HTTP/2)은 http:// 주소에 h2c 업그레이드 요청을 보내는데,
    // 업그레이드 요청을 직접 처리하는 서버(Next.js 등)는 그 연결을 끊어 로그아웃 토큰이 전달되지 않는다
    private val httpClient = HttpClient.newBuilder().version(HttpClient.Version.HTTP_1_1).connectTimeout(Duration.ofSeconds(3)).build()
    private val executor = Executors.newVirtualThreadPerTaskExecutor()

    /** 이 로그인 세션에서 토큰을 받은 클라이언트들. 저장된 ID 토큰 claim 의 sid 를 함께 읽는다 (ID 토큰이 없으면 sid 없이 sub 만) */
    fun targetsBySession(sessionId: Long): List<LogoutTarget> {
        val rows = jdbcTemplate.query(
            """
            SELECT a.registered_client_id, a.principal_name,
                   JSON_UNQUOTE(JSON_EXTRACT(CONVERT(a.oidc_id_token_metadata USING utf8mb4), '$."metadata.token.claims".sid')) AS sid
            FROM login_session_authorization l JOIN oauth2_authorization a ON a.id = l.authorization_id
            WHERE l.session_id = ?
            """,
            { rs, _ -> Triple(rs.getString(1), rs.getString(2), rs.getString(3)?.takeUnless { it == "null" }) },
            sessionId,
        ).distinct()
        return rows.mapNotNull { (registeredClientId, subjectId, sid) -> target(registeredClientId, subjectId)?.copy(sid = sid) }
    }

    fun targetsBySubject(subjectId: Long): List<LogoutTarget> =
        targets("SELECT registered_client_id, principal_name FROM oauth2_authorization WHERE principal_name = ?", subjectId.toString())

    @TransactionalEventListener(phase = TransactionPhase.AFTER_COMMIT, fallbackExecution = true)
    fun onLogout(event: BackChannelLogoutEvent) {
        event.targets.forEach { target -> executor.submit { send(target) } }
    }

    private fun targets(sql: String, arg: Any): List<LogoutTarget> {
        val rows = jdbcTemplate.query(sql, { rs, _ -> rs.getString(1) to rs.getString(2) }, arg).distinct()
        return rows.mapNotNull { (registeredClientId, subjectId) -> target(registeredClientId, subjectId) }
    }

    private fun target(registeredClientId: String, subjectId: String): LogoutTarget? {
        val client = ssoClientRepository.findByRegisteredClientId(registeredClientId) ?: return null
        val uri = client.backchannelLogoutUri ?: return null
        return LogoutTarget(client.clientCode, uri, subjectId)
    }

    private fun send(target: LogoutTarget) {
        try {
            val body = "logout_token=" + URLEncoder.encode(logoutToken(target), Charsets.UTF_8)
            val request = HttpRequest.newBuilder(URI(target.logoutUri))
                .timeout(Duration.ofSeconds(5))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build()
            val status = httpClient.send(request, HttpResponse.BodyHandlers.discarding()).statusCode()
            if (status !in 200..299) log.warn("back-channel 로그아웃 응답 {}: client={}", status, target.clientId)
        } catch (e: Exception) {
            log.warn("back-channel 로그아웃 전송 실패: client={} ({}: {})", target.clientId, e.javaClass.simpleName, e.message)
        }
    }

    private fun logoutToken(target: LogoutTarget): String {
        val now = clock.instant()
        val claims = JwtClaimsSet.builder()
            .issuer(properties.issuer)
            .audience(listOf(target.clientId))
            .subject(target.subjectId)
            .issuedAt(now)
            .expiresAt(now.plusSeconds(120))
            .id(UUID.randomUUID().toString())
            .claim("events", mapOf(LOGOUT_EVENT to emptyMap<String, Any>()))
            .apply { target.sid?.let { claim("sid", it) } }
            .build()
        val header = JwsHeader.with(SignatureAlgorithm.RS256).type("logout+jwt").build()
        return encoder.encode(JwtEncoderParameters.from(header, claims)).tokenValue
    }

    companion object {
        const val LOGOUT_EVENT = "http://schemas.openid.net/event/backchannel-logout"
    }
}
