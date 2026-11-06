package com.didrakon.iam.authn.config

import org.springframework.boot.context.properties.ConfigurationProperties
import java.net.URI
import java.time.Duration

/** 인증 정책. application.yml 의 iam.authn.* */
@ConfigurationProperties("iam.authn")
data class AuthnProperties(
    /** 토큰 iss. 외부에서 접속하는 주소 */
    val issuer: String = "http://localhost:8080",
    /** 관리 콘솔 주소. IAM 홈에서 내 정보·2단계 인증·관리 화면으로 가는 링크에 쓴다 */
    val consoleUrl: String = "http://localhost:3000",
    /** 연속 실패 허용 횟수. 넘으면 [lockDuration] 동안 잠근다 */
    val maxFailedAttempts: Int = 5,
    val lockDuration: Duration = Duration.ofMinutes(30),
    val passwordMinLength: Int = 10,
    /** 비밀번호 만료 기간. null 이면 만료 없음 */
    val passwordMaxAge: Duration? = Duration.ofDays(90),
    /** IdP 로그인 세션 유지 시간 */
    val sessionTimeout: Duration = Duration.ofHours(8),
    /** MFA 비밀값 암호화 키 (Base64, 32바이트). 운영에서는 반드시 환경변수로 주입한다 */
    val secretKey: String = "",
    /** JWT 서명 키 (PEM). 비어 있으면 기동할 때 만든다 (재기동하면 기존 토큰이 무효) */
    val jwtPrivateKey: String = "",
    val jwtPublicKey: String = "",
    /** true 면 서명 키가 없을 때 기동하지 않는다 (운영 프로필) */
    val requirePersistentJwtKey: Boolean = false,
    val webauthn: WebAuthn = WebAuthn(),
) {
    /**
     * 패스키(WebAuthn) 신뢰 당사자 설정. 비우면 [issuer] 에서 정한다 (rpId = 호스트, 허용 출처 = issuer 의 출처).
     * 브라우저는 보안 컨텍스트에서만 패스키를 쓴다: localhost 는 http 도 되지만 그 밖에는 https 여야 한다.
     * rpId 는 등록한 패스키에 묶이므로 운영 중에 바꾸면 기존 패스키를 쓸 수 없다.
     */
    data class WebAuthn(
        val rpId: String = "",
        val allowedOrigins: Set<String> = emptySet(),
    )

    fun webauthnRpId(): String = webauthn.rpId.ifBlank { URI.create(issuer).host ?: throw IllegalStateException("issuer 에 호스트가 없습니다: $issuer") }

    fun webauthnAllowedOrigins(): Set<String> = webauthn.allowedOrigins.ifEmpty {
        val uri = URI.create(issuer)
        setOf(URI(uri.scheme, null, uri.host, uri.port, null, null, null).toString())
    }
}
