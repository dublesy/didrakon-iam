# Spring Boot 빠른 시작

Spring Boot 3 + Spring Security OAuth2 Client 로 IAM 에 붙는 방법. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고, 여기에는 Spring 에서 하는 법만 둔다.

예제: [`examples/integration/spring-boot/`](../../examples/integration/spring-boot/) (포트 4101)

## 1. 준비물

| 항목 | 버전 |
|---|---|
| JDK | 17 |
| Spring Boot | 3.5.16 (Spring Security 6.5.11) |
| 의존성 | `spring-boot-starter-web`, `spring-boot-starter-oauth2-client` |
| 빌드 | Gradle 8.14.3 (wrapper 포함) |

JWT 검증(Nimbus)은 `oauth2-client` 에 들어 있다. 다른 라이브러리는 필요 없다.

## 2. IAM 클라이언트 등록 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-spring-boot` |
| 유형 | `WEB`, 기밀 |
| 리다이렉트 URI | `http://localhost:4101/callback` |
| 로그아웃 알림 주소 | `http://localhost:4101/backchannel-logout` |

Spring 기본 리다이렉트 주소는 `/login/oauth2/code/{registrationId}` 다. 예제는 계약에 맞춰 `/callback` 으로 바꿨다. 기본값을 쓰면 IAM 에도 그 주소를 등록한다.

## 3. 설정

[`application.yml`](../../examples/integration/spring-boot/src/main/resources/application.yml)

```yaml
spring.security.oauth2.client:
  registration.iam:
    client-id: ${IAM_CLIENT_ID}
    client-secret: ${IAM_CLIENT_SECRET}
    client-authentication-method: client_secret_basic
    authorization-grant-type: authorization_code
    redirect-uri: "{baseUrl}/callback"
    scope: openid,profile
  provider.iam:
    issuer-uri: ${IAM_ISSUER}      # discovery 로 나머지 주소를 읽는다
webhook.secret: ${WEBHOOK_SECRET}
```

| 환경변수 | 뜻 |
|---|---|
| `IAM_ISSUER` | `http://localhost:8080` |
| `IAM_CLIENT_ID`, `IAM_CLIENT_SECRET` | 등록할 때 받은 값. `run.sh` 가 `.env.local` 의 `SPRING_BOOT_CLIENT_ID`·`SPRING_BOOT_CLIENT_SECRET` 를 넘긴다 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값. 없으면 시작하지 않는다 |

`issuer-uri` 를 쓰면 **시작할 때** discovery 문서를 읽는다. IAM 이 꺼져 있으면 앱이 뜨지 않는다.

## 4. 핵심 코드

### 로그인·콜백 — [`SecurityConfig.java`](../../examples/integration/spring-boot/src/main/java/sample/iam/SecurityConfig.java)

```java
http
    .authorizeHttpRequests(a -> a.requestMatchers("/me").authenticated().anyRequest().permitAll())
    .exceptionHandling(e -> e.authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
    .csrf(c -> c.ignoringRequestMatchers("/backchannel-logout", "/webhooks/iam"))
    .oauth2Login(o -> o
        .authorizationEndpoint(a -> a.authorizationRequestResolver(loginResolver(clients)))  // GET /login
        .redirectionEndpoint(r -> r.baseUri("/callback"))
        .successHandler((req, res, auth) -> { /* 계정 연결 → 세션 색인 → /me */ }))
    .logout(l -> l
        .logoutRequestMatcher(path.matcher(HttpMethod.GET, "/logout"))
        .logoutSuccessHandler(new OidcClientInitiatedLogoutSuccessHandler(clients)));  // id_token_hint
```

```java
var resolver = new DefaultOAuth2AuthorizationRequestResolver(clients, "/oauth2/authorization");
resolver.setAuthorizationRequestCustomizer(OAuth2AuthorizationRequestCustomizers.withPkce());
```

- `state`·`nonce` 는 기본으로 붙는다. **PKCE 는 기밀 클라이언트에 기본으로 붙지 않으므로** `withPkce()` 를 건다.
- ID 토큰 검증(JWKS 서명, `iss`, `aud`, `exp`, `iat`, `nonce`)은 `OidcAuthorizationCodeAuthenticationProvider` 가 한다. 따로 코드를 쓰지 않는다.
- claim 은 `OidcUser` 에서 읽는다: `getSubject()`, `getClaimAsString("emp_no")`, `getClaimAsStringList("roles")`, `getClaimAsString("sid")`.

### 계정 연결 — [`LocalUsers.java`](../../examples/integration/spring-boot/src/main/java/sample/iam/LocalUsers.java)

```java
LocalUser user = findBySubject(sub)              // iam_subject_id
        .or(() -> findUnlinkedByEmpNo(empNo))      // 사번 (아직 연결 안 된 계정만)
        .orElseGet(() -> save(new LocalUser(...)));// JIT
user.iamSubjectId = sub;
```

로컬 계정이 꺼져 있으면(퇴사 처리) 성공 핸들러가 세션을 버리고 `403` 을 준다.

### back-channel 로그아웃 — [`BackChannelLogoutController.java`](../../examples/integration/spring-boot/src/main/java/sample/iam/BackChannelLogoutController.java)

```java
NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri)
        .jwtProcessorCustomizer(p -> p.setJWSTypeVerifier(
                new DefaultJOSEObjectTypeVerifier<>(new JOSEObjectType("logout+jwt"))))
        .build();
decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
        JwtValidators.createDefaultWithIssuer(issuer),           // exp, iss
        check(jwt -> jwt.getAudience().contains(clientId), "aud"),
        check(jwt -> jwt.getIssuedAt() != null, "iat"),
        check(jwt -> jwt.getClaims().get("events") instanceof Map<?, ?> e && e.containsKey(EVENT), "events"),
        check(jwt -> !jwt.hasClaim("nonce"), "nonce"),
        check(jwt -> jwt.getSubject() != null || jwt.hasClaim("sid"), "sub or sid")));
```

검증에 실패하면 `400`, 통과하면 [`SessionIndex`](../../examples/integration/spring-boot/src/main/java/sample/iam/SessionIndex.java)로 `sid` 의 세션(없으면 `sub` 의 모든 세션)을 `invalidate()` 하고 `200`.

**Spring Security 내장 기능(`http.oidcLogout(...)`)을 쓰지 않은 이유**

| | 내장 `oidcLogout().backChannel()` | 예제 (직접 구현) |
|---|---|---|
| 받는 주소 | `/logout/connect/back-channel/{registrationId}` | `/backchannel-logout` (모든 예제와 같은 주소) |
| 세션 종료 | `sid`→세션 색인을 찾은 뒤 앱 자신의 `/logout` 을 HTTP 로 다시 부른다 | 세션 색인에서 바로 `invalidate()` |
| 퇴사 웹훅 | 그 색인을 웹훅에서 쓰기 어렵다 | 같은 색인으로 `sub` 의 세션을 끝낸다 |

내장 기능도 서명·`typ`·`iss`·`aud`·`events`·`nonce` 를 검증한다. 웹훅으로 세션을 끝낼 일이 없으면 써도 된다. 쓰면 IAM 로그아웃 알림 주소를 `http://localhost:4101/logout/connect/back-channel/iam` 으로 등록하고, 서버 여러 대·프록시 뒤에서는 앱이 자신의 `/logout` 을 부를 수 있는 주소(`logoutUri`)를 맞춰 준다.

### 웹훅 — [`WebhookController.java`](../../examples/integration/spring-boot/src/main/java/sample/iam/WebhookController.java)

```java
@PostMapping("/webhooks/iam")
ResponseEntity<?> receive(@RequestBody byte[] body, @RequestHeader("X-Didrakon-Delivery") String delivery,
                          @RequestHeader("X-Didrakon-Timestamp") String ts,
                          @RequestHeader("X-Didrakon-Signature") String sig) {
    if (!validSignature(ts, body, sig)) return status(401);   // MessageDigest.isEqual (상수 시간)
    if (!fresh(ts)) return status(401);                         // 300초
    if (!processed.add(delivery)) return ok(duplicate);         // 실제로는 DB 테이블
    // user.status_changed + RETIRED → users.disable(sub); sessions.end(sub, null);
}
```

중복 거르기는 예제라 메모리 `Set` 이다. 실제로는 `webhook_delivery(delivery_id PRIMARY KEY, received_at)` 같은 테이블에 넣고, 이미 있으면 `200` 만 준다.

## 5. 실행·검증

```bash
cd examples/integration/spring-boot
./run.sh                                   # ../.env.local 을 읽어 4101 로 띄운다
python3 ../verify.py http://localhost:4101
```

클라이언트를 등록하기 전에는 웹훅만 확인할 수 있다: `python3 ../verify.py http://localhost:4101 --webhook-only`

## 6. 주의할 점

- **웹훅 본문은 `byte[]`(또는 `String`)로 받는다.** DTO 로 받아 다시 직렬화하면 공백·순서가 달라져 서명이 맞지 않는다.
- **`/backchannel-logout`·`/webhooks/iam` 은 CSRF 예외로 둔다.** 빼먹으면 `403` 이 나고 IAM 은 실패로 보고 재시도한다.
- **로그아웃 토큰을 `JwtDecoder` 기본값으로 읽으면 실패한다.** Spring 의 기본 형식 검사기는 `typ` 가 `JWT` 인 것만 받는다. `logout+jwt` 만 받도록 바꾼다 (`validateType(false)` 로 끄기만 하면 ID 토큰을 로그아웃 토큰으로 보내는 공격을 못 막는다).
- **세션이 메모리에 있다.** 서버가 여러 대면 Spring Session(JDBC·Redis)을 쓰고, 세션에 `sub`·`sid` 를 저장해 그 값으로 찾아 지운다. 그렇지 않으면 back-channel 요청을 받은 서버만 세션을 끝낸다.
- **`/me` 같은 API 는 401 을 준다.** 기본 진입점은 로그인 화면으로 302 를 보내 SPA·API 호출에서 엉뚱한 HTML 을 받는다. 예제는 `HttpStatusEntryPoint(401)` 를 쓴다.
- `OidcClientInitiatedLogoutSuccessHandler` 에 `setPostLogoutRedirectUri` 를 주면 그 주소도 IAM 에 등록해야 한다. 예제는 `id_token_hint` 만 보낸다.
