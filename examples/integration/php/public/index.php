<?php
declare(strict_types=1);

/**
 * DIDRAKON IAM 연동 예제 (PHP + jumbojett/openid-connect-php).
 * 계약은 ../../README.md, 공통 규칙은 docs/integration/README.md 를 따른다.
 *
 * - 세션은 PHP 기본 세션(서버의 파일). 로그인한 세션은 SQLite 에 (sub, sid) 로 색인해 back-channel 로그아웃이 찾아 끝낸다
 * - jumbojett 1.0.2 는 state 를 code 교환 뒤에야 비교하고, nonce·exp 가 없으면 통과시키고, 서명 알고리즘을 고정하지 않으며,
 *   로그아웃 토큰의 typ·exp·events 를 보지 않는다. 이 빈틈은 아래 checkIdToken·verifyLogoutToken 에서 직접 확인한다
 */

use Jumbojett\OpenIDConnectClient;

require __DIR__ . '/../vendor/autoload.php';
require __DIR__ . '/../src/Store.php';

const BACKCHANNEL_EVENT = 'http://schemas.openid.net/event/backchannel-logout';
const WEBHOOK_MAX_CLOCK_SKEW = 300; // 초

$issuer = getenv('IAM_ISSUER') ?: 'http://localhost:8080';
$clientId = getenv('CLIENT_ID') ?: 'sample-php';
$clientSecret = getenv('CLIENT_SECRET') ?: 'dummy-secret';
$baseUrl = getenv('APP_BASE_URL') ?: 'http://localhost:4107';
$webhookSecret = getenv('WEBHOOK_SECRET') ?: '';

ini_set('session.use_strict_mode', '1');   // 모르는 세션 ID 를 받아 쓰지 않는다 (세션 고정 방지)
ini_set('session.cookie_httponly', '1');
ini_set('session.cookie_samesite', 'Lax');
session_name('app_session');

$store = new Store((getenv('DATA_DIR') ?: sys_get_temp_dir()) . '/sample-php.db');

function iamClient(): OpenIDConnectClient
{
    global $issuer, $clientId, $clientSecret, $baseUrl;
    // issuer 만 주면 discovery 문서에서 주소를 읽는다. 토큰 교환은 client_secret_basic
    $oidc = new OpenIDConnectClient($issuer, $clientId, $clientSecret);
    $oidc->setRedirectURL($baseUrl . '/callback');
    $oidc->addScope(['profile']);              // openid 는 라이브러리가 붙인다
    $oidc->setCodeChallengeMethod('S256');     // PKCE
    return $oidc;
}

// ---- 라우팅 ----

$route = $_SERVER['REQUEST_METHOD'] . ' ' . parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
try {
    match ($route) {
        'GET /login' => login(),
        'GET /callback' => callback(),
        'GET /me' => me(),
        'GET /logout' => logout(),
        'POST /backchannel-logout' => backchannelLogout(),
        'POST /webhooks/iam' => webhook(),
        default => json(404, ['error' => 'not_found']),
    };
} catch (Throwable $e) {
    error_log('요청 처리 실패: ' . $e->getMessage());
    json(500, ['error' => 'server_error']);
}

// ---- 로그인 ----

function login(): void
{
    session_start();
    // state·nonce·PKCE code_verifier 를 세션에 두고 IAM 인가 주소로 보낸다 (header + exit)
    iamClient()->authenticate();
}

function callback(): void
{
    global $store;
    session_start();
    // jumbojett 은 code 를 교환한 뒤에 state 를 비교하므로, 교환 전에 직접 확인한다
    $state = $_SESSION['openid_connect_state'] ?? '';
    $nonce = $_SESSION['openid_connect_nonce'] ?? '';
    if ($state === '' || !hash_equals($state, (string) ($_GET['state'] ?? ''))) {
        json(400, ['error' => 'state 가 맞지 않습니다']);
    }
    if (isset($_GET['error'])) {
        json(401, ['error' => 'IAM 로그인 실패: ' . $_GET['error']]);
    }

    try {
        $oidc = iamClient();
        $oidc->authenticate();   // code 교환(client_secret_basic + code_verifier) → 서명(JWKS)·iss·aud·exp 검증
        $claims = $oidc->getVerifiedClaims();
        checkIdToken($oidc->getIdToken(), $claims, $nonce);
    } catch (Throwable $e) {
        error_log('ID 토큰 검증 실패: ' . $e->getMessage());
        json(401, ['error' => 'ID 토큰 검증 실패']);
    }

    $user = $store->linkAccount($claims->sub, $claims->emp_no ?? null, $claims->name ?? null);
    if (!$user['active']) {
        json(403, ['error' => '이 시스템에서 사용 중지된 계정입니다']);
    }

    session_regenerate_id(true);   // 로그인 전 세션 ID 를 버린다
    $_SESSION = [
        'sub' => $claims->sub,
        'name' => $claims->name ?? null,
        'empNo' => $claims->emp_no ?? null,
        'roles' => (array) ($claims->roles ?? []),
        'sid' => $claims->sid ?? null,
        'localUserId' => (int) $user['id'],
        'idToken' => $oidc->getIdToken(),
    ];
    $store->indexSession(session_id(), $claims->sub, $claims->sid ?? null);
    redirect('/me');
}

/** jumbojett 이 느슨하게 보는 것: 서명 알고리즘 고정(HS256 위조 차단), nonce·exp 는 반드시 있어야 한다 */
function checkIdToken(string $idToken, object $claims, string $nonce): void
{
    if ((jwtPart($idToken, 0)->alg ?? '') !== 'RS256') {
        throw new RuntimeException('alg 가 RS256 이 아닙니다');
    }
    if ($nonce === '' || !hash_equals($nonce, (string) ($claims->nonce ?? ''))) {
        throw new RuntimeException('nonce 가 맞지 않습니다');
    }
    if (!is_int($claims->exp ?? null) || $claims->exp < time()) {
        throw new RuntimeException('만료된 ID 토큰입니다');
    }
}

function me(): void
{
    if (!isset($_COOKIE[session_name()])) {
        json(401, ['error' => 'unauthorized']);
    }
    session_start(['read_and_close' => true]);
    if (!isset($_SESSION['sub'])) {
        json(401, ['error' => 'unauthorized']);
    }
    json(200, [
        'sub' => $_SESSION['sub'],
        'name' => $_SESSION['name'],
        'empNo' => $_SESSION['empNo'],
        'roles' => $_SESSION['roles'],
        'localUserId' => $_SESSION['localUserId'],
        'sid' => $_SESSION['sid'],
    ]);
}

function logout(): void
{
    global $store;
    session_start();
    $idToken = $_SESSION['idToken'] ?? null;
    $store->forgetSession(session_id());
    session_destroy();
    setcookie(session_name(), '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'samesite' => 'Lax']);
    if ($idToken === null) {
        redirect('/me');
    }
    // IAM 로그인 세션까지 끝낸다. post_logout_redirect_uri 를 쓰려면 IAM 에 등록한 값이어야 한다
    iamClient()->signOut($idToken, null);
}

// ---- back-channel 로그아웃 ----

function backchannelLogout(): void
{
    global $store;
    try {
        $claims = verifyLogoutToken((string) ($_POST['logout_token'] ?? ''));
    } catch (Throwable $e) {
        error_log('logout_token 거부: ' . $e->getMessage());
        json(400, ['error' => 'invalid logout_token']);
    }
    // sid 가 있으면 그 로그인 세션만, 없으면 sub 의 모든 세션
    endSessions($store->sessionIds($claims->sub ?? null, $claims->sid ?? null));
    json(200, ['ok' => true]);
}

function verifyLogoutToken(string $token): object
{
    $header = jwtPart($token, 0);
    if (($header->typ ?? '') !== 'logout+jwt' || ($header->alg ?? '') !== 'RS256') {
        throw new RuntimeException('typ 가 logout+jwt 가 아니거나 alg 가 RS256 이 아닙니다');
    }
    // 라이브러리: 서명(JWKS)·iss·aud·iat·nonce 없음·sub 또는 sid 있음
    if (!iamClient()->verifyLogoutToken()) {
        throw new RuntimeException('logout_token claim 이 맞지 않습니다');
    }
    // 라이브러리가 보지 않는 것: exp, events 가 반드시 있어야 한다
    $claims = jwtPart($token, 1);
    if (!is_int($claims->exp ?? null) || $claims->exp < time()) {
        throw new RuntimeException('만료된 logout_token 입니다');
    }
    if (!is_object($claims->events->{BACKCHANNEL_EVENT} ?? null)) {
        throw new RuntimeException('back-channel logout 이벤트가 없습니다');
    }
    return $claims;
}

/** 남의 세션을 끝낸다: 그 세션 ID 로 열어 지운다. 호출한 쪽(IAM)에 세션 쿠키를 보내지 않게 쿠키를 끈다 */
function endSessions(array $sessionIds): void
{
    global $store;
    ini_set('session.use_cookies', '0');
    foreach ($sessionIds as $id) {
        session_id($id);
        session_start();
        session_destroy();
        $store->forgetSession($id);
    }
}

// ---- 웹훅 ----

function webhook(): void
{
    global $store, $webhookSecret;
    $body = file_get_contents('php://input');   // 받은 바이트 그대로 서명을 검증한다
    $timestamp = $_SERVER['HTTP_X_DIDRAKON_TIMESTAMP'] ?? '';
    $expected = 'sha256=' . hash_hmac('sha256', $timestamp . '.' . $body, $webhookSecret);
    if ($webhookSecret === '' || !hash_equals($expected, $_SERVER['HTTP_X_DIDRAKON_SIGNATURE'] ?? '')) {
        json(401, ['error' => 'bad signature']);
    }
    if (!ctype_digit($timestamp) || abs(time() - (int) $timestamp) > WEBHOOK_MAX_CLOCK_SKEW) {
        json(401, ['error' => 'stale timestamp']);
    }
    if (!$store->firstDelivery($_SERVER['HTTP_X_DIDRAKON_DELIVERY'] ?? '')) {
        json(200, ['duplicate' => true]);
    }

    $event = json_decode($body, true);
    if (($event['type'] ?? '') === 'user.status_changed' && ($event['data']['status'] ?? '') === 'RETIRED') {
        $sub = (string) $event['data']['subjectId'];
        $store->disableBySubject($sub);          // 실제 시스템은 권한도 모두 회수한다
        endSessions($store->sessionIds($sub));
    }
    json(200, ['ok' => true]);
}

// ---- 도우미 ----

function jwtPart(string $jwt, int $index): ?object
{
    $part = explode('.', $jwt)[$index] ?? '';
    $decoded = json_decode((string) base64_decode(strtr($part, '-_', '+/')), false);
    return is_object($decoded) ? $decoded : null;
}

function json(int $status, array $body): never
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode($body, JSON_UNESCAPED_UNICODE);
    exit;
}

function redirect(string $location): never
{
    header('Location: ' . $location, true, 302);
    exit;
}
