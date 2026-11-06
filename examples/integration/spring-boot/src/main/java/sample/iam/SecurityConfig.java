package sample.iam;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.savedrequest.NullRequestCache;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
public class SecurityConfig {

    static final String REGISTRATION_ID = "iam";

    @Bean
    SecurityFilterChain security(HttpSecurity http, ClientRegistrationRepository clients,
                                 LocalUsers users, SessionIndex sessionIndex) throws Exception {
        PathPatternRequestMatcher.Builder path = PathPatternRequestMatcher.withDefaults();
        http
            .authorizeHttpRequests(a -> a
                .requestMatchers("/me").authenticated()
                .anyRequest().permitAll())
            // 로그인하지 않았으면 로그인 화면으로 보내지 않고 401
            .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            // 로그인 뒤에는 항상 /me 로 간다. 401 난 요청을 세션에 저장하지 않는다
            .requestCache(c -> c.requestCache(new NullRequestCache()))
            // IAM 이 서버 간에 부르는 주소는 CSRF 토큰이 없다 (서명으로 검증한다)
            .csrf(c -> c.ignoringRequestMatchers("/backchannel-logout", "/webhooks/iam"))
            .oauth2Login(o -> o
                .authorizationEndpoint(a -> a.authorizationRequestResolver(loginResolver(clients)))
                .redirectionEndpoint(r -> r.baseUri("/callback"))
                .successHandler((request, response, authentication) -> {
                    OidcUser oidc = (OidcUser) authentication.getPrincipal();
                    LocalUsers.LocalUser user = users.link(
                            oidc.getSubject(), oidc.getClaimAsString("emp_no"), oidc.getFullName());
                    if (!user.enabled) {
                        request.getSession().invalidate();
                        response.sendError(HttpStatus.FORBIDDEN.value(), "disabled local account");
                        return;
                    }
                    request.getSession().setAttribute("localUserId", user.id);
                    sessionIndex.register(request.getSession(), oidc.getSubject(), oidc.getClaimAsString("sid"));
                    response.sendRedirect("/me");
                }))
            // GET /logout: 앱 세션을 지우고 IAM /connect/logout?id_token_hint=... 로 보낸다
            .logout(l -> l
                .logoutRequestMatcher(path.matcher(HttpMethod.GET, "/logout"))
                .logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clients)));
        return http.build();
    }

    /**
     * GET /login 을 IAM 인가 요청으로 바꾼다 (기본 주소는 /oauth2/authorization/iam).
     * 기밀 클라이언트도 PKCE(S256)를 쓰게 한다. state·nonce 는 기본으로 붙는다.
     */
    private OAuth2AuthorizationRequestResolver loginResolver(ClientRegistrationRepository clients) {
        var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
        resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
        return new OAuth2AuthorizationRequestResolver() {
            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
                return "/login".equals(request.getRequestURI())
                        ? resolver.resolve(request, REGISTRATION_ID)
                        : resolver.resolve(request);
            }

            @Override
            public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String registrationId) {
                return resolver.resolve(request, registrationId);
            }
        };
    }
}
