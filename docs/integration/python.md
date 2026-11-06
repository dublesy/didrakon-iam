# Python 빠른 시작 (FastAPI)

FastAPI 에 [Authlib](https://docs.authlib.org/) 의 Starlette OAuth 클라이언트로 IAM 에 붙인다. 공통 규칙(토큰 claim, 로그아웃 토큰 검증, 웹훅 서명)은 [연동 가이드](README.md)에 있고 여기서는 Python 코드만 다룬다.

예제: [`examples/integration/python/`](../../examples/integration/python/) — 파일 하나([`app.py`](../../examples/integration/python/app.py))에 계약의 모든 주소가 있다. 사용자·세션·처리한 웹훅 전달은 SQLite 파일(`app.db`) 하나에 둔다.

## 1. 준비물

| 항목 | 버전 |
|---|---|
| Python | 3.14 (로컬 `python3` 로 확인. 3.12 이상이면 된다) |
| `fastapi` | 0.162.0 |
| `uvicorn` | 0.54.0 |
| `Authlib` | 1.9.4 (discovery, 인가 URL·PKCE·nonce, code 교환, ID 토큰 검증) |
| `joserfc` | 1.8.0 (back-channel 로그아웃 토큰 검증. Authlib 이 내부에서 쓰는 JOSE 라이브러리) |
| `httpx2` | 2.16.0 (Authlib 의 HTTP 클라이언트. `httpx` 를 쓰면 사용 중단 경고가 난다) |
| `python-multipart` | 0.0.33 (`request.form()` 으로 `logout_token` 을 읽는 데 필요) |

버전은 [`requirements.txt`](../../examples/integration/python/requirements.txt) 에 고정했다. Docker 는 쓰지 않는다.

## 2. IAM 에 등록할 값

| 항목 | 값 |
|---|---|
| 클라이언트 코드 | `sample-python` |
| 유형 / 기밀 | `WEB` / 켬 |
| 리다이렉트 URI | `http://localhost:4104/callback` |
| 로그아웃 알림 주소 | `http://localhost:4104/backchannel-logout` |

## 3. 설정

| 환경변수 | 뜻 | 기본값 |
|---|---|---|
| `IAM_ISSUER` | IAM 주소 | `http://localhost:8080` |
| `CLIENT_ID`, `CLIENT_SECRET` | 등록한 클라이언트 코드·비밀값 | `sample-python`, 임시값 |
| `WEBHOOK_SECRET` | 웹훅 서명 비밀값 | 없음 (없으면 웹훅을 모두 `401`) |
| `APP_URL` | 리다이렉트 URI 를 만들 앱 주소 | `http://localhost:4104` |
| `DB_PATH` | SQLite 파일 | `app.db` |

[`run.sh`](../../examples/integration/python/run.sh) 가 `examples/integration/.env.local` 의 `PYTHON_CLIENT_ID`·`PYTHON_CLIENT_SECRET` 을 `CLIENT_ID`·`CLIENT_SECRET` 으로 넘기고, `.venv` 를 만들어 의존성을 설치한 뒤 uvicorn 으로 띄운다. discovery 는 처음 `/login` 할 때 읽는다.

## 4. 핵심 코드

**클라이언트 등록** — issuer 의 discovery 주소만 주면 모든 주소와 JWKS 를 얻는다. `code_challenge_method` 를 주면 PKCE(S256)를, scope 에 `openid` 가 있으면 nonce 를 Authlib 이 알아서 만든다.

```python
oauth.register(
    "iam",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,  # 토큰 교환은 client_secret_basic (Authlib 기본값)
    client_kwargs={"scope": "openid profile", "code_challenge_method": "S256"},
)
```

**서버 세션** — Authlib 은 `state`·`nonce`·`code_verifier` 를 `request.session` 에 둔다. 흔히 쓰는 Starlette `SessionMiddleware` 는 세션 전체를 서명한 쿠키라 back-channel 로그아웃으로 끝낼 수 없으므로, 예제는 `request.session` 을 SQLite 행으로 채우는 작은 미들웨어([`server_session`](../../examples/integration/python/app.py))를 둔다. 쿠키에는 세션 ID 만 가고, 행에 `sub` 와 ID 토큰의 `sid` 를 따로 적어 둔다.

```sql
create table app_session (id text primary key, sub text, iam_sid text, data text not null);
```

**로그인·콜백** — `authorize_access_token` 한 번이 `state` 확인 → code 교환(`code_verifier` 포함) → ID 토큰 검증(JWKS 서명, `iss`, `aud`, `exp`, `nonce`)을 모두 한다. 검증한 claim 은 `token["userinfo"]` 에 있다.

```python
@app.get("/login")
async def login(request: Request):
    return await oauth.iam.authorize_redirect(request, f"{APP_URL}/callback")

@app.get("/callback")
async def callback(request: Request):
    try:
        token = await oauth.iam.authorize_access_token(request)
    except OAuthError as e:
        return JSONResponse({"error": e.error}, status_code=400)
    claims = token["userinfo"]          # sub, name, emp_no, roles, sid ...
    user = link_account(claims)
    ...
    request.scope["rotate_session"] = True  # 로그인하면 세션 ID 를 새로 발급 (세션 고정 방지)
    return RedirectResponse("/me", status_code=302)
```

**계정 연결** — `iam_subject_id` → `emp_no` → JIT 순서. 이메일로는 연결하지 않는다 ([`link_account`](../../examples/integration/python/app.py)).

```python
user = db.execute("select * from local_user where iam_subject_id = ?", (sub,)).fetchone()
if user is None and emp_no:
    user = db.execute("select * from local_user where emp_no = ? and iam_subject_id is null", (emp_no,)).fetchone()
    if user is not None:
        db.execute("update local_user set iam_subject_id = ? where id = ?", (sub, user["id"]))
if user is None:
    db.execute("insert into local_user (iam_subject_id, emp_no, name) values (?, ?, ?)", ...)
```

**back-channel 로그아웃** — Authlib 에는 로그아웃 토큰 검증 함수가 없다. Authlib 이 받아 둔 JWKS 로 `joserfc` 가 서명을 보고, claim 은 `JWTClaimsRegistry` 와 직접 비교로 본다. 모르는 `kid` 면 JWKS 를 다시 받는다.

```python
token = jwt.decode(value, KeySet.import_key_set(await oauth.iam.fetch_jwk_set()), registry=registry)
if token.header.get("typ") != "logout+jwt": raise ValueError(...)
jwt.JWTClaimsRegistry(
    leeway=60,
    iss={"essential": True, "value": ISSUER},
    aud={"essential": True, "value": CLIENT_ID},   # aud 가 배열이면 그중 하나
    iat={"essential": True},
    exp={"essential": True},
).validate(token.claims)
# events 에 back-channel 이벤트가 있는지, nonce 가 없는지 직접 확인
```

`sid` 가 있으면 `delete from app_session where iam_sid = ?`, 없으면 `where sub = ?` 로 지운다. 검증에 실패하면 `400` ([`backchannel_logout`](../../examples/integration/python/app.py)).

**웹훅** — `await request.body()` 로 받은 바이트 그대로 HMAC 을 계산하고 `hmac.compare_digest` 로 비교한다.

```python
raw = await request.body()
expected = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, signature): return 401
if abs(time.time() - int(timestamp)) > 300: return 401
# X-Didrakon-Delivery 를 webhook_delivery(id primary key) 에 넣어 보고, 이미 있으면 200 만
```

`user.status_changed` 가 `RETIRED` 면 `local_user.active = 0` 으로 끄고 그 `sub` 의 세션 행을 지운다. 꺼진 로컬 계정은 다시 로그인해도 콜백에서 `403` 이다 ([`webhook`](../../examples/integration/python/app.py)).

## 5. 실행·검증

```bash
cd examples/integration/python
./run.sh                                   # .venv 생성·설치 후 uvicorn (포트 4104)

# 다른 터미널에서
cd examples/integration
python3 verify.py http://localhost:4104                  # 로그인·웹훅·back-channel 전체
python3 verify.py http://localhost:4104 --webhook-only   # 클라이언트 등록 전: 웹훅만
```

## 6. 주의할 점

- **Starlette `SessionMiddleware` 로 로그인 상태를 두지 않는다.** 서명한 쿠키 세션은 서버가 지울 수 없어 back-channel 로그아웃·퇴사 웹훅으로 끝낼 수 없다. 운영에서는 세션을 Redis·DB 에 둔다.
- **로그아웃 토큰의 `typ` 를 꼭 본다.** 로그아웃 토큰과 ID 토큰은 같은 키로 서명되므로, `typ` 를 보지 않으면 ID 토큰을 로그아웃 토큰처럼 보내 남의 세션을 끊을 수 있다. `JWSRegistry(strict_check_header=False)` 는 `typ` 같은 헤더를 막지 않을 뿐 검사하지 않는다.
- Authlib 의 ID 토큰 검증은 `exp`·`iat` 에 120초 여유를 둔다. 서버 시각은 NTP 로 맞춘다.
- 리다이렉트 URI 는 `request.url_for("callback")` 대신 설정값(`APP_URL`)으로 만든다. 프록시 뒤에서는 `url_for` 가 `http://내부주소` 를 만들어 IAM 에 등록한 값과 달라진다.
- 예제는 SQLite 연결 하나를 이벤트 루프에서 함께 쓴다. 운영 DB 에서는 연결 풀(SQLAlchemy 등)을 쓰고, 처리한 웹훅 전달 ID 의 오래된 행을 지운다.
- 운영에서는 issuer 와 앱 주소가 https 이고, 세션 쿠키에 `secure=True` 를 준다. `SameSite=Lax` 여야 IAM 에서 돌아오는 `/callback` 에 쿠키가 붙는다.

## Django 라면

[mozilla-django-oidc](https://mozilla-django-oidc.readthedocs.io/) 를 쓴다. 예제는 따로 두지 않는다.

- discovery 를 읽지 않으므로 `OIDC_OP_AUTHORIZATION_ENDPOINT`·`OIDC_OP_TOKEN_ENDPOINT`·`OIDC_OP_USER_ENDPOINT`·`OIDC_OP_JWKS_ENDPOINT` 를 [연동 가이드의 주소](README.md#3-로그인-흐름)로 직접 넣고, `OIDC_RP_SIGN_ALGO = "RS256"`, `OIDC_RP_SCOPES = "openid profile"`, `OIDC_USE_PKCE = True` 로 둔다. nonce 는 기본으로 켜져 있다.
- **기본 계정 연결이 이메일이다.** `OIDCAuthenticationBackend` 를 상속해 `filter_users_by_claims` 를 `iam_subject_id`(`sub`) → `emp_no` 순서로 바꾸고, `create_user` 에서 `iam_subject_id` 를 저장한다. 기본 구현은 `/userinfo` 응답으로 사용자를 찾는데 IAM 의 userinfo 에는 `emp_no`·`roles` 가 없으므로, `get_userinfo` 를 고쳐 검증한 ID 토큰 payload 를 쓴다.
- back-channel 로그아웃은 라이브러리에 없다. 위 [back-channel 로그아웃](#4-핵심-코드) 검증을 뷰로 만들고(`csrf_exempt`), 세션은 DB·캐시 백엔드(`django.contrib.sessions`)에 두어 로그인할 때 `sid`·`sub` 를 세션에 적고 그 세션 행을 지운다. `signed_cookies` 세션 백엔드는 쓰지 않는다.
