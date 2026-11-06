package sample.iam;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.proc.DefaultJOSEObjectTypeVerifier;
import java.util.List;
import java.util.Map;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

/**
 * OIDC Back-Channel Logout 1.0. IAM 이 사용자 로그아웃·세션 강제 종료·비밀번호 변경·사용 중지 때 서버에서 직접 부른다.
 * 로그아웃·세션 하나 종료면 sid 가 오고, 사용자 단위(비밀번호 변경·사용 중지·모든 세션 끊기)면 sub 만 온다.
 */
@RestController
public class BackChannelLogoutController {

    private static final String EVENT = "http://schemas.openid.net/event/backchannel-logout";

    private final JwtDecoder decoder;
    private final SessionIndex sessions;

    public BackChannelLogoutController(ClientRegistrationRepository clients, SessionIndex sessions) {
        ClientRegistration iam = clients.findByRegistrationId(SecurityConfig.REGISTRATION_ID);
        String issuer = iam.getProviderDetails().getIssuerUri();
        String clientId = iam.getClientId();

        NimbusJwtDecoder decoder = NimbusJwtDecoder
                .withJwkSetUri(iam.getProviderDetails().getJwkSetUri())
                // 기본 검사기는 typ 이 JWT 인 것만 받는다. 로그아웃 토큰은 logout+jwt 만 받는다
                .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(
                        new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("logout+jwt"))))
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(issuer),   // exp·nbf, iss
                check(jwt -> jwt.getAudience() != null && jwt.getAudience().contains(clientId), "aud"),
                check(jwt -> jwt.getIssuedAt() != null, "iat"),
                check(jwt -> jwt.getClaims().get("events") instanceof Map<?, ?> e && e.containsKey(EVENT), "events"),
                check(jwt -> !jwt.hasClaim("nonce"), "nonce"),
                check(jwt -> jwt.getSubject() != null || jwt.hasClaim("sid"), "sub or sid")));
        this.decoder = decoder;
        this.sessions = sessions;
    }

    @PostMapping(value = "/backchannel-logout", consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    ResponseEntity<Map<String, Object>> logout(@RequestParam(name = "logout_token", required = false) String token) {
        Jwt jwt;
        try {
            if (token == null) throw new JwtException("logout_token missing");
            jwt = decoder.decode(token);
        } catch (JwtException e) {
            return ResponseEntity.badRequest()
                    .header("Cache-Control", "no-store")
                    .body(Map.of("error", "invalid_request"));
        }
        // sid 가 있으면 그 로그인 세션 하나만, 없으면 sub 의 세션을 모두 끝낸다
        int ended = sessions.end(jwt.getSubject(), jwt.getClaimAsString("sid"));
        return ResponseEntity.ok().header("Cache-Control", "no-store").body(Map.of("ended", ended));
    }

    private static OAuth2TokenValidator<Jwt> check(java.util.function.Predicate<Jwt> ok, String claim) {
        OAuth2TokenValidatorResult failure =
                OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "bad " + claim, null));
        return jwt -> ok.test(jwt) ? OAuth2TokenValidatorResult.success() : failure;
    }
}
