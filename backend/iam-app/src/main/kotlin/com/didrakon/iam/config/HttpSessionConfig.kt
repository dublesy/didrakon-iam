package com.didrakon.iam.config

import org.springframework.beans.factory.annotation.Value
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.core.session.SessionRegistry
import org.springframework.session.FindByIndexNameSessionRepository
import org.springframework.session.Session
import org.springframework.session.security.SpringSessionBackedSessionRegistry
import org.springframework.session.web.http.CookieSerializer
import org.springframework.session.web.http.DefaultCookieSerializer

/**
 * 브라우저(HTTP) 세션은 DB 에 둔다 (Spring Session JDBC, 테이블은 Flyway V22). 재기동·배포에도 IdP 로그인이 유지되고 여러 인스턴스가 함께 쓴다.
 * 세션에 넣는 값은 JDK 직렬화로 저장되므로 Serializable 이어야 한다.
 */
@Configuration
class HttpSessionConfig {
    /**
     * 세션 쿠키. Spring Boot 는 내장 서버면 server.servlet.session.cookie.*, 그 밖(MockMvc 등)이면 서블릿 설정을 따라 이름이 달라지므로 여기서 고정한다.
     * Secure 는 [secureCookie] 면 늘 붙이고, 아니면 요청이 HTTPS 일 때만 붙는다. 운영은 늘 붙인다 — 프록시가 보낸 HTTPS 정보를 믿는 설정이 틀려도
     * 쿠키가 평문 HTTP 로 나가지 않게
     */
    @Bean
    fun cookieSerializer(@Value("\${iam.authn.secure-session-cookie:false}") secureCookie: Boolean): CookieSerializer = DefaultCookieSerializer().apply {
        setCookieName("JSESSIONID") // 이전(Tomcat 세션)과 같은 이름
        setUseHttpOnlyCookie(true)
        setSameSite("Lax")
        if (secureCookie) setUseSecureCookie(true)
    }

    /**
     * 로그인·인가 서버(SAS)가 RP 로그아웃의 sid 확인에 쓰는 세션 목록. 없으면 SAS 가 서버 메모리에 따로 두어,
     * 세션을 DB 에 두는 지금은 다른 인스턴스의 세션을 모르고 지워지지도 않아 메모리가 계속 늘어난다
     */
    @Bean
    fun <S : Session> sessionRegistry(sessions: FindByIndexNameSessionRepository<S>): SessionRegistry = SpringSessionBackedSessionRegistry(sessions)
}
