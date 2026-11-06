package com.didrakon.iam.config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
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
     * Secure 는 요청이 HTTPS 일 때 붙는다 (운영은 forward-headers-strategy 로 프록시 뒤의 HTTPS 를 안다)
     */
    @Bean
    fun cookieSerializer(): CookieSerializer = DefaultCookieSerializer().apply {
        setCookieName("JSESSIONID") // 이전(Tomcat 세션)과 같은 이름
        setUseHttpOnlyCookie(true)
        setSameSite("Lax")
    }
}
