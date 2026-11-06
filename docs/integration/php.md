# PHP 빠른 시작

PHP 에 [jumbojett/openid-connect-php](https://github.com/jumbojett/OpenID-Connect-PHP) 로 IAM 에 붙인다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고 여기서는 PHP 코드만 다룬다.

예제: [`examples/integration/php/`](../../examples/integration/php/) — 주소는 [`public/index.php`](../../examples/integration/php/public/index.php), 사용자·세션 색인·웹훅 중복 기록은 [`src/Store.php`](../../examples/integration/php/src/Store.php)(SQLite).

## 1. 준비물

| 항목 | 버전 |
|---|---|
| PHP | 8.3 (예제는 Docker `php:8.3.36-cli-trixie`, 확장 `curl`·`pdo_sqlite`) |
| Composer | 2.8 |
| `jumbojett/openid-connect-php` | v1.0.2 (discovery, PKCE, state·nonce, code 교환, JWKS 서명 검증) |
| `phpseclib/phpseclib` | 3.0.58 (jumbojett 이 RS256 검증에 씀) |

버전은 [`composer.json`](../../examples/integration/php/composer.json)·`composer.lock` 에 고정했다. 로컬에 PHP 가 없어도 Docker 만 있으면 된다.

**왜 jumbojett 인가**: 인가 요청부터 ID 토큰 서명 검증, back-channel 로그아웃 토큰 검증까지 한 클래스에 있어 코드가 가장 짧다. 다만 아래 [주의할 점](#6-주의할-점)의 빈틈이 있어 몇 줄을 직접 확인한다. 빈틈을 직접 메우기 싫으면 `league/oauth2-client`(인가·교환) + `firebase/php-jwt`(JWKS 서명·claim 검증) 조합이 대안이다.

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-php` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4107/callback` |
| 로그아웃 알림 주소 | `http://localhost:4107/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 | `sample-php`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | 없음 (없으면 모든 웹훅 `401`) |
| `APP_BASE_URL` | 리다이렉트 URI 를 만들 앱 주소 | `http://localhost:4107` |
| `DATA_DIR` | SQLite 파일 위치 | 컨테이너 `/tmp` |

[`run.sh`](../../examples/integration/php/run.sh) 가 `examples/integration/.env.local` 의 `PHP_CLIENT_ID`·`PHP_CLIENT_SECRET` 을 `CLIENT_ID`·`CLIENT_SECRET` 으로 넘기고 이미지를 만들어 띄운다. 컨테이너 안에서도 IAM 이 `http://localhost:8080` 이어야 토큰 `iss` 와 맞으므로, [`docker-entrypoint.sh`](../../examples/integration/php/docker-entrypoint.sh) 가 socat 으로 컨테이너의 8080 을 호스트로 넘긴다.

## 4. 핵심 코드

**클라이언트** — issuer 만 주면 discovery 로 주소를 읽는다. 토큰 교환은 discovery 의 `client_secret_basic` 을 골라 쓴다.

```php
$oidc = new OpenIDConnectClient($issuer, $clientId, $clientSecret);
$oidc->setRedirectURL($baseUrl . '/callback');
$oidc->addScope(['profile']);            // openid 는 라이브러리가 붙인다
$oidc->setCodeChallengeMethod('S256');   // PKCE
```

**로그인** — `authenticate()` 가 `state`·`nonce`·`code_verifier` 를 `$_SESSION` 에 두고 IAM 으로 보낸다(`header` + `exit`).

**콜백** — 같은 `authenticate()` 가 code 를 교환하고 서명·`iss`·`aud`·`exp` 를 본다. 라이브러리가 느슨하게 보는 것은 앞뒤에서 직접 확인한다.

```php
// jumbojett 은 code 를 교환한 "뒤에" state 를 비교한다 → 교환 전에 먼저 본다
$state = $_SESSION['openid_connect_state'] ?? '';
$nonce = $_SESSION['openid_connect_nonce'] ?? '';
if ($state === '' || !hash_equals($state, $_GET['state'] ?? '')) { /* 400 */ }

$oidc->authenticate();
$claims = $oidc->getVerifiedClaims();
checkIdToken($oidc->getIdToken(), $claims, $nonce);   // alg RS256 고정, nonce·exp 필수
```

그다음 계정을 잇고(`sub` → `emp_no` → JIT, [`Store::linkAccount`](../../examples/integration/php/src/Store.php)), `session_regenerate_id(true)` 로 세션 ID 를 바꾼 뒤 사용자 정보와 ID 토큰을 세션에 둔다. **세션 ID 를 `(sub, sid)` 로 SQLite 에 색인한다.** PHP 세션 파일만으로는 "이 사용자의 세션"을 찾을 수 없어서다.

```php
$store->indexSession(session_id(), $claims->sub, $claims->sid ?? null);
```

**back-channel 로그아웃** — 라이브러리의 `verifyLogoutToken()` 이 서명·`iss`·`aud`·`iat`·`nonce` 없음을 보고, `typ`·`alg`·`exp`·`events` 는 직접 본다.

```php
if ((jwtPart($token, 0)->typ ?? '') !== 'logout+jwt') { /* 400 */ }
if (!$oidc->verifyLogoutToken()) { /* 400 */ }             // $_POST['logout_token']
$claims = jwtPart($token, 1);
// exp 가 지나지 않았고, events 에 backchannel-logout 이 있어야 한다
```

끝낼 세션은 색인에서 찾는다(`sid` 가 있으면 그 세션만, 없으면 `sub` 의 모든 세션). 남의 세션은 그 ID 로 열어 지운다. 이때 세션 쿠키를 꺼서, 호출한 IAM 에 세션 ID 가 응답 헤더로 나가지 않게 한다.

```php
ini_set('session.use_cookies', '0');
foreach ($sessionIds as $id) {
    session_id($id); session_start(); session_destroy();
    $store->forgetSession($id);
}
```

**웹훅** — `php://input` 의 바이트 그대로 서명하고 `hash_equals` 로 상수 시간 비교한다.

```php
$body = file_get_contents('php://input');
$expected = 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $webhookSecret);
if (!hash_equals($expected, $_SERVER['HTTP_X_DIDRAKON_SIGNATURE'] ?? '')) { /* 401 */ }
```

그다음 시각(300초), `X-Didrakon-Delivery` 중복(`INSERT OR IGNORE`)을 보고, `user.status_changed` 가 `RETIRED` 면 로컬 계정을 끄고 그 사용자의 세션을 모두 지운다.

## 5. 실행·검증

```bash
cd examples/integration/php
./run.sh                                   # docker build + run (포트 4107)

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4107                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4107 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **jumbojett v1.0.2 의 빈틈은 직접 메운다.** 예제의 `checkIdToken`·`verifyLogoutToken` 이 그 몫이다.
  - `state` 를 code 교환 뒤에야 비교한다 → 교환 전에 비교
  - ID 토큰에 `nonce`·`exp` 가 **없으면** 통과시킨다 → 둘 다 필수로
  - 서명 알고리즘을 고정하지 않아 `HS256`(client secret 으로 서명)도 받는다 → `RS256` 만
  - 로그아웃 토큰의 `typ`·`exp` 를 보지 않고, `events` 가 없어도 통과시킨다 → 직접 확인
- JWKS 를 검증할 때마다 다시 받는다(캐시 없음). 요청이 많으면 JWKS 를 APCu 등에 캐시하는 하위 클래스를 둔다.
- `authenticate()`·`signOut()` 은 안에서 `header()` 뒤 `exit` 한다. 프레임워크 응답 객체를 쓰는 곳에서는 그 뒤 코드가 돌지 않는 것을 감안한다.
- 세션은 `session.use_strict_mode=1`, `HttpOnly`, `SameSite=Lax` 로 둔다. 운영은 https 이므로 `session.cookie_secure=1` 도 켠다.
- 서버가 여러 대면 세션 저장소(Redis 등)와 세션 색인을 함께 공유해야 back-channel 로그아웃이 어느 서버에 와도 세션을 끝낼 수 있다.
- 예제는 PHP 내장 서버(`php -S`, 작업자 4개)로 띄운다. 운영은 php-fpm + nginx/Apache 로 둔다.

### Laravel 이라면

[Laravel Socialite](https://laravel.com/docs/socialite) 에는 OIDC 드라이버가 없으므로 [SocialiteProviders](https://socialiteproviders.com/) 의 범용 OIDC 공급자(예: `socialiteproviders/oidc` 계열 패키지)를 붙여 issuer·client 를 설정한다. 이때 이 문서와 같은 점을 확인한다.

- ID 토큰 서명(JWKS)·`iss`·`aud`·`exp`·`nonce` 를 그 패키지가 실제로 검증하는지 (안 하면 위 `checkIdToken` 처럼 직접)
- PKCE(`S256`)를 켰는지 (`->enablePKCE()`)
- back-channel 로그아웃은 Socialite 범위 밖이다. `/backchannel-logout` 라우트를 따로 만들고(CSRF 예외), 세션 드라이버를 `database`·`redis` 로 두어 `sub`·`sid` 로 세션을 찾아 지운다
- 웹훅도 CSRF 예외 라우트에서 `$request->getContent()` 의 원문으로 서명을 검증한다
