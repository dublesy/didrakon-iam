//! DIDRAKON IAM 연동 예제 (Rust + axum + openidconnect).
//! 계약은 ../README.md, 공통 규칙은 docs/integration/README.md 를 따른다.
//! 사용자·세션·처리한 웹훅은 메모리에 둔다. 실제 시스템은 DB 를 쓴다.

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Bytes;
use axum::extract::rejection::FormRejection;
use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Json, Redirect, Response};
use axum::routing::{get, post};
use axum::Router;
use axum_extra::extract::cookie::{Cookie, CookieJar, SameSite};
use hmac::{Hmac, Mac};
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use openidconnect::core::*;
use openidconnect::{
    reqwest, AdditionalClaims, AdditionalProviderMetadata, AuthenticationFlow, AuthorizationCode,
    Client, ClientId, ClientSecret, CsrfToken, EmptyExtraTokenFields, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IdTokenFields, IssuerUrl, Nonce, PkceCodeChallenge,
    PkceCodeVerifier, ProviderMetadata, RedirectUrl, Scope, StandardErrorResponse,
    StandardTokenResponse, TokenResponse,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Sha256;

const COOKIE: &str = "app_session";
const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";
const WEBHOOK_MAX_SKEW_SECS: i64 = 300;

// ---- openidconnect 타입: IAM 이 ID 토큰에 넣는 추가 claim 과 discovery 의 로그아웃 주소 ----

#[derive(Clone, Debug, Deserialize, Serialize)]
struct IamClaims {
    emp_no: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    sid: Option<String>,
}
impl AdditionalClaims for IamClaims {}

#[derive(Clone, Debug, Deserialize, Serialize)]
struct LogoutMetadata {
    end_session_endpoint: Option<String>,
}
impl AdditionalProviderMetadata for LogoutMetadata {}

type IamProviderMetadata = ProviderMetadata<
    LogoutMetadata, CoreAuthDisplay, CoreClientAuthMethod, CoreClaimName, CoreClaimType,
    CoreGrantType, CoreJweContentEncryptionAlgorithm, CoreJweKeyManagementAlgorithm,
    CoreJsonWebKey, CoreResponseMode, CoreResponseType, CoreSubjectIdentifierType,
>;
type IamTokenResponse = StandardTokenResponse<
    IdTokenFields<IamClaims, EmptyExtraTokenFields, CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm, CoreJwsSigningAlgorithm>,
    CoreTokenType,
>;
type IamClient = Client<
    IamClaims, CoreAuthDisplay, CoreGenderClaim, CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey, CoreAuthPrompt, StandardErrorResponse<CoreErrorResponseType>,
    IamTokenResponse, CoreTokenIntrospectionResponse, CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet, EndpointNotSet, EndpointNotSet, EndpointNotSet, EndpointMaybeSet, EndpointMaybeSet,
>;

// ---- 앱 상태 ----

/// 이 시스템의 사용자. `iam_subject_id` 가 IAM `sub` 와 잇는 키다.
#[allow(dead_code)] // name 은 예제에서 읽지 않는다
struct LocalUser {
    id: u64,
    iam_subject_id: Option<String>,
    emp_no: Option<String>,
    name: Option<String>,
    active: bool,
}

/// 서버에 두는 세션. 로그인 전에는 state·nonce·PKCE 만, 로그인 뒤에는 사용자 정보를 담는다.
#[derive(Default)]
struct Session {
    state: String,
    nonce: String,
    pkce_verifier: String,
    user: Option<LoggedIn>,
}

struct LoggedIn {
    sub: String,
    name: Option<String>,
    emp_no: Option<String>,
    roles: Vec<String>,
    sid: Option<String>,
    id_token: String,
    local_user_id: u64,
}

#[derive(Default)]
struct Store {
    sessions: HashMap<String, Session>, // 쿠키 값 → 세션
    users: Vec<LocalUser>,
    deliveries: HashSet<String>, // 처리한 X-Didrakon-Delivery
}

struct AppState {
    issuer: String,
    client_id: String,
    webhook_secret: Vec<u8>,
    client: IamClient,
    http: reqwest::Client,
    jwks_uri: String,
    end_session_endpoint: Option<String>,
    store: Mutex<Store>,
}
type App = Arc<AppState>;

#[tokio::main]
async fn main() {
    let issuer = env("IAM_ISSUER", "http://localhost:8080");
    let port = env("PORT", "4106");
    let base_url = env("APP_BASE_URL", &format!("http://localhost:{port}"));
    let client_id = env("CLIENT_ID", "sample-rust");

    // 리다이렉트를 따라가지 않는 HTTP 클라이언트 (SSRF 방지, openidconnect 권장)
    let http = reqwest::ClientBuilder::new()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("HTTP 클라이언트");
    // discovery 문서와 JWKS 를 읽고 issuer 가 같은지 확인한다. 로컬은 http, 운영은 반드시 https
    let metadata = IamProviderMetadata::discover_async(IssuerUrl::new(issuer.clone()).unwrap(), &http)
        .await
        .expect("IAM discovery 실패");
    let jwks_uri = metadata.jwks_uri().url().to_string();
    let end_session_endpoint = metadata.additional_metadata().end_session_endpoint.clone();
    let client: IamClient = Client::from_provider_metadata(
        metadata,
        ClientId::new(client_id.clone()),
        Some(ClientSecret::new(env("CLIENT_SECRET", "dummy-secret"))), // 토큰 교환은 client_secret_basic
    )
    .set_redirect_uri(RedirectUrl::new(format!("{base_url}/callback")).unwrap());

    let store = Store {
        // 미리 있던 로컬 계정 (iam_subject_id 가 비어 있어 첫 로그인 때 사번으로 연결된다)
        users: vec![LocalUser {
            id: 1, iam_subject_id: None, emp_no: Some("D-001".into()),
            name: Some("기존 사용자".into()), active: true,
        }],
        ..Default::default()
    };
    let app = Arc::new(AppState {
        issuer: issuer.clone(),
        client_id: client_id.clone(),
        webhook_secret: std::env::var("WEBHOOK_SECRET").unwrap_or_default().into_bytes(),
        client, http, jwks_uri, end_session_endpoint,
        store: Mutex::new(store),
    });

    let router = Router::new()
        .route("/login", get(login))
        .route("/callback", get(callback))
        .route("/me", get(me))
        .route("/logout", get(logout))
        .route("/backchannel-logout", post(backchannel_logout))
        .route("/webhooks/iam", post(webhook))
        .with_state(app);

    println!("sample-rust: {base_url} (client_id={client_id}, issuer={issuer})");
    let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{port}")).await.unwrap();
    axum::serve(listener, router).await.unwrap();
}

// ---- 로그인 ----

async fn login(State(app): State<App>, jar: CookieJar) -> (CookieJar, Redirect) {
    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (url, state, nonce) = app
        .client
        .authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        )
        .add_scope(Scope::new("profile".into()))
        .set_pkce_challenge(challenge)
        .url();
    let session = Session {
        state: state.secret().clone(),
        nonce: nonce.secret().clone(),
        pkce_verifier: verifier.secret().clone(),
        user: None,
    };
    (start_session(&app, jar, session), Redirect::to(url.as_str()))
}

async fn callback(
    State(app): State<App>,
    jar: CookieJar,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    // 로그인 전 세션을 꺼낸다 (한 번만 쓴다)
    let old_id = jar.get(COOKIE).map(|c| c.value().to_string()).unwrap_or_default();
    let Some(pending) = app.store.lock().unwrap().sessions.remove(&old_id) else {
        return (StatusCode::BAD_REQUEST, "로그인 세션이 없습니다").into_response();
    };
    if pending.state.is_empty() || q.get("state") != Some(&pending.state) {
        return (StatusCode::BAD_REQUEST, "state 가 맞지 않습니다").into_response();
    }
    let Some(code) = q.get("code") else {
        return (StatusCode::UNAUTHORIZED, "IAM 로그인 실패").into_response();
    };

    let token = match app
        .client
        .exchange_code(AuthorizationCode::new(code.clone()))
        .expect("토큰 주소")
        .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
        .request_async(&app.http)
        .await
    {
        Ok(t) => t,
        Err(e) => {
            eprintln!("code 교환 실패: {e:?}");
            return (StatusCode::UNAUTHORIZED, "code 교환 실패").into_response();
        }
    };
    let Some(id_token) = token.id_token() else {
        return (StatusCode::UNAUTHORIZED, "ID 토큰이 없습니다").into_response();
    };
    // 서명(JWKS)·iss·aud·exp·nonce 를 검증한다
    let claims = match id_token.claims(&app.client.id_token_verifier(), &Nonce::new(pending.nonce)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("ID 토큰 검증 실패: {e:?}");
            return (StatusCode::UNAUTHORIZED, "ID 토큰 검증 실패").into_response();
        }
    };
    let extra = claims.additional_claims();
    let sub = claims.subject().to_string();
    let name = claims.name().and_then(|n| n.get(None)).map(|n| n.to_string());

    let Some(local_user_id) = link_account(&app, &sub, extra.emp_no.as_deref(), name.as_deref()) else {
        return (StatusCode::FORBIDDEN, "사용이 중지된 계정입니다").into_response();
    };
    // 로그인하면 세션 ID 를 새로 만든다 (세션 고정 공격 방지)
    let session = Session {
        user: Some(LoggedIn {
            sub, name, local_user_id,
            emp_no: extra.emp_no.clone(),
            roles: extra.roles.clone(),
            sid: extra.sid.clone(),
            id_token: id_token.to_string(),
        }),
        ..Default::default()
    };
    (start_session(&app, jar, session), Redirect::to("/me")).into_response()
}

/// iam_subject_id 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다 (JIT).
/// 이메일로는 연결하지 않는다. 사용 중지된 계정이면 None.
fn link_account(app: &App, sub: &str, emp_no: Option<&str>, name: Option<&str>) -> Option<u64> {
    let mut store = app.store.lock().unwrap();
    let users = &mut store.users;
    let idx = users
        .iter()
        .position(|u| u.iam_subject_id.as_deref() == Some(sub))
        .or_else(|| {
            let emp_no = emp_no?;
            let i = users.iter().position(|u| u.iam_subject_id.is_none() && u.emp_no.as_deref() == Some(emp_no))?;
            users[i].iam_subject_id = Some(sub.to_string());
            Some(i)
        })
        .unwrap_or_else(|| {
            users.push(LocalUser {
                id: users.len() as u64 + 1,
                iam_subject_id: Some(sub.to_string()),
                emp_no: emp_no.map(str::to_string),
                name: name.map(str::to_string),
                active: true,
            });
            users.len() - 1
        });
    users[idx].active.then_some(users[idx].id)
}

async fn me(State(app): State<App>, jar: CookieJar) -> Response {
    let store = app.store.lock().unwrap();
    let user = jar.get(COOKIE).and_then(|c| store.sessions.get(c.value())).and_then(|s| s.user.as_ref());
    match user {
        None => (StatusCode::UNAUTHORIZED, Json(json!({"error": "unauthorized"}))).into_response(),
        Some(u) => Json(json!({
            "sub": u.sub, "name": u.name, "empNo": u.emp_no, "roles": u.roles,
            "localUserId": u.local_user_id, "sid": u.sid,
        }))
        .into_response(),
    }
}

async fn logout(State(app): State<App>, jar: CookieJar) -> (CookieJar, Redirect) {
    let session = jar
        .get(COOKIE)
        .and_then(|c| app.store.lock().unwrap().sessions.remove(c.value()));
    let jar = jar.remove(Cookie::build(COOKIE).path("/"));
    let id_token = session.and_then(|s| s.user).map(|u| u.id_token);
    match (id_token, &app.end_session_endpoint) {
        // IAM 로그인 세션까지 끝낸다. post_logout_redirect_uri 를 쓰려면 IAM 에 등록한 값이어야 한다
        (Some(t), Some(end)) => {
            let mut url = reqwest::Url::parse(end).unwrap();
            url.query_pairs_mut().append_pair("id_token_hint", &t);
            (jar, Redirect::to(url.as_str()))
        }
        _ => (jar, Redirect::to("/")),
    }
}

// ---- back-channel 로그아웃 ----

#[derive(Deserialize)]
struct LogoutForm {
    logout_token: String,
}

#[derive(Deserialize)]
struct LogoutClaims {
    sub: Option<String>,
    sid: Option<String>,
    #[allow(dead_code)]
    iat: u64, // 없으면 역직렬화가 실패한다
    #[serde(default)]
    events: serde_json::Map<String, serde_json::Value>,
    nonce: Option<serde_json::Value>,
}

async fn backchannel_logout(State(app): State<App>, form: Result<Form<LogoutForm>, FormRejection>) -> StatusCode {
    let Ok(Form(form)) = form else { return StatusCode::BAD_REQUEST };
    let claims = match verify_logout_token(&app, &form.logout_token).await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("logout_token 거부: {e}");
            return StatusCode::BAD_REQUEST;
        }
    };
    let mut store = app.store.lock().unwrap();
    store.sessions.retain(|_, s| match (&s.user, &claims.sid) {
        // sid 가 있으면 그 IAM 로그인 세션 하나만, 없으면 sub 의 세션 모두
        (Some(u), Some(sid)) => u.sid.as_ref() != Some(sid),
        (Some(u), None) => Some(&u.sub) != claims.sub.as_ref(),
        (None, _) => true,
    });
    StatusCode::OK
}

async fn verify_logout_token(app: &App, token: &str) -> Result<LogoutClaims, String> {
    let header = jsonwebtoken::decode_header(token).map_err(|e| e.to_string())?;
    // ID 토큰을 로그아웃 토큰으로 재사용하지 못하게 typ 를 확인한다
    if header.typ.as_deref() != Some("logout+jwt") {
        return Err("typ 가 logout+jwt 가 아닙니다".into());
    }
    // 서명 키는 IAM JWKS 에서 kid 로 찾는다 (키 교체에도 맞게 매번 읽는다. 운영은 캐시)
    let kid = header.kid.ok_or("kid 가 없습니다")?;
    let body = app.http.get(&app.jwks_uri).send().await
        .and_then(|r| r.error_for_status()).map_err(|e| e.to_string())?
        .bytes().await.map_err(|e| e.to_string())?;
    let jwks: JwkSet = serde_json::from_slice(&body).map_err(|e| e.to_string())?;
    let jwk = jwks.find(&kid).ok_or("JWKS 에 kid 가 없습니다")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|e| e.to_string())?;

    // 서명(RS256)·iss·aud·exp 검증
    let mut v = Validation::new(Algorithm::RS256);
    v.set_issuer(&[&app.issuer]);
    v.set_audience(&[&app.client_id]);
    v.set_required_spec_claims(&["exp", "iss", "aud"]);
    let c = jsonwebtoken::decode::<LogoutClaims>(token, &key, &v).map_err(|e| e.to_string())?.claims;

    if c.nonce.is_some() {
        return Err("nonce 가 있으면 안 됩니다".into());
    }
    if !c.events.contains_key(BACKCHANNEL_EVENT) {
        return Err("back-channel logout 이벤트가 없습니다".into());
    }
    if c.sub.is_none() && c.sid.is_none() {
        return Err("sub 와 sid 가 모두 없습니다".into());
    }
    Ok(c)
}

// ---- 웹훅 ----

#[derive(Deserialize)]
struct WebhookEvent {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    data: serde_json::Value,
}

async fn webhook(State(app): State<App>, headers: HeaderMap, body: Bytes) -> Response {
    let header = |name: &str| headers.get(name).and_then(|v| v.to_str().ok()).unwrap_or("");
    let ts = header("X-Didrakon-Timestamp");
    // 받은 바이트 그대로 서명을 검증한다 (JSON 으로 다시 직렬화하지 않는다)
    if !valid_signature(&app.webhook_secret, ts, &body, header("X-Didrakon-Signature")) {
        return (StatusCode::UNAUTHORIZED, "bad signature").into_response();
    }
    let fresh = ts.parse::<i64>().is_ok_and(|sent| (now_secs() - sent).abs() <= WEBHOOK_MAX_SKEW_SECS);
    if !fresh {
        return (StatusCode::UNAUTHORIZED, "stale timestamp").into_response();
    }
    // 같은 전달이 두 번 올 수 있다. 처리한 전달 ID 는 다시 처리하지 않는다
    let first_time = app.store.lock().unwrap().deliveries.insert(header("X-Didrakon-Delivery").to_string());
    if !first_time {
        return Json(json!({"duplicate": true})).into_response();
    }

    let Ok(ev) = serde_json::from_slice::<WebhookEvent>(&body) else {
        return (StatusCode::BAD_REQUEST, "bad json").into_response();
    };
    if ev.kind == "user.status_changed" && ev.data["status"] == "RETIRED" {
        retire(&app, &ev.data["subjectId"].to_string());
    }
    Json(json!({"ok": true})).into_response()
}

fn valid_signature(secret: &[u8], ts: &str, body: &[u8], header: &str) -> bool {
    let Some(Ok(got)) = header.strip_prefix("sha256=").map(hex::decode) else { return false };
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).expect("HMAC 는 어떤 길이의 키도 받는다");
    mac.update(ts.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac.verify_slice(&got).is_ok() // 상수 시간 비교
}

/// 퇴사자의 로컬 계정을 끄고 세션을 모두 끝낸다
fn retire(app: &App, sub: &str) {
    let sub = sub.trim_matches('"'); // subjectId 가 숫자든 문자열이든 같은 값으로
    let mut store = app.store.lock().unwrap();
    for u in store.users.iter_mut().filter(|u| u.iam_subject_id.as_deref() == Some(sub)) {
        u.active = false;
    }
    store.sessions.retain(|_, s| s.user.as_ref().is_none_or(|u| u.sub != sub));
}

// ---- 세션·도우미 ----

fn start_session(app: &App, jar: CookieJar, session: Session) -> CookieJar {
    let id = CsrfToken::new_random_len(32).secret().clone();
    app.store.lock().unwrap().sessions.insert(id.clone(), session);
    // 운영(https)에서는 .secure(true)
    jar.add(Cookie::build((COOKIE, id)).path("/").http_only(true).same_site(SameSite::Lax))
}

fn now_secs() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs() as i64
}

fn env(key: &str, fallback: &str) -> String {
    std::env::var(key).ok().filter(|v| !v.is_empty()).unwrap_or_else(|| fallback.to_string())
}
