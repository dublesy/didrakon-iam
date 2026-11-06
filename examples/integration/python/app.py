"""DIDRAKON IAM 연동 예제 — FastAPI + Authlib.

계약은 ../README.md. 사용자·세션·웹훅 전달 기록을 SQLite 한 파일(app.db)에 둔다.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time

from authlib.integrations.starlette_client import OAuth, OAuthError
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, RedirectResponse, Response
from joserfc import jwt
from joserfc.errors import InvalidKeyIdError, JoseError
from joserfc.jwk import KeySet
from joserfc.jws import JWSRegistry

ISSUER = os.environ.get("IAM_ISSUER", "http://localhost:8080").rstrip("/")
CLIENT_ID = os.environ.get("CLIENT_ID", "sample-python")
CLIENT_SECRET = os.environ.get("CLIENT_SECRET", "change-me")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
APP_URL = os.environ.get("APP_URL", "http://localhost:4104")
SESSION_COOKIE = "sample_python_sid"
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

# ── 저장소 ──────────────────────────────────────────────────────────────
db = sqlite3.connect(os.environ.get("DB_PATH", "app.db"), isolation_level=None, check_same_thread=False)
db.row_factory = sqlite3.Row
db.executescript("""
create table if not exists local_user (
  id             integer primary key,
  iam_subject_id text unique,          -- IAM sub. 연결 뒤에는 이 값으로만 찾는다
  emp_no         text unique,
  name           text,
  active         integer not null default 1
);
create table if not exists app_session (
  id      text primary key,            -- 쿠키에는 이 값만 간다
  sub     text,                        -- back-channel 로그아웃이 sub 로 찾는다
  iam_sid text,                        -- ID 토큰의 sid. back-channel 로그아웃이 sid 로 찾는다
  data    text not null
);
create table if not exists webhook_delivery (
  id          text primary key,
  received_at integer not null
);
""")

app = FastAPI()
oauth = OAuth()
oauth.register(
    "iam",
    server_metadata_url=f"{ISSUER}/.well-known/openid-configuration",
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,  # 토큰 교환은 client_secret_basic (Authlib 기본값)
    client_kwargs={"scope": "openid profile", "code_challenge_method": "S256"},
)


# ── 서버 세션 ───────────────────────────────────────────────────────────
# Authlib 는 state·nonce·code_verifier 를 request.session 에 둔다. 그 session 을 SQLite 행으로 채워
# 쿠키에는 세션 ID 만 가게 한다 (세션을 쿠키에 담으면 back-channel 로그아웃으로 끝낼 수 없다).
@app.middleware("http")
async def server_session(request: Request, call_next):
    sid = request.cookies.get(SESSION_COOKIE)
    row = db.execute("select data from app_session where id = ?", (sid,)).fetchone() if sid else None
    if row is None:
        sid = None
    request.scope["session"] = json.loads(row["data"]) if row else {}
    response = await call_next(request)

    data = request.scope["session"]
    if sid and (not data or request.scope.get("rotate_session")):
        db.execute("delete from app_session where id = ?", (sid,))
        sid = None
    if data:
        user = data.get("user") or {}
        if sid:  # 다른 요청(back-channel)이 지웠으면 되살리지 않는다
            db.execute("update app_session set sub = ?, iam_sid = ?, data = ? where id = ?",
                       (user.get("sub"), data.get("sid"), json.dumps(data), sid))
        else:
            sid = secrets.token_urlsafe(32)
            db.execute("insert into app_session (id, sub, iam_sid, data) values (?, ?, ?, ?)",
                       (sid, user.get("sub"), data.get("sid"), json.dumps(data)))
            response.set_cookie(SESSION_COOKIE, sid, httponly=True, samesite="lax")
    elif request.cookies.get(SESSION_COOKIE):
        response.delete_cookie(SESSION_COOKIE)
    return response


# ── 계정 연결 ───────────────────────────────────────────────────────────
def link_account(claims) -> sqlite3.Row:
    """iam_subject_id → emp_no → 새로 만들기(JIT). 이메일로는 연결하지 않는다."""
    sub, emp_no = claims["sub"], claims.get("emp_no")
    user = db.execute("select * from local_user where iam_subject_id = ?", (sub,)).fetchone()
    if user is None and emp_no:
        user = db.execute("select * from local_user where emp_no = ? and iam_subject_id is null", (emp_no,)).fetchone()
        if user is not None:
            db.execute("update local_user set iam_subject_id = ? where id = ?", (sub, user["id"]))
    if user is None:
        db.execute("insert into local_user (iam_subject_id, emp_no, name) values (?, ?, ?)",
                   (sub, emp_no, claims.get("name")))
    return db.execute("select * from local_user where iam_subject_id = ?", (sub,)).fetchone()


# ── 로그인·로그아웃 ─────────────────────────────────────────────────────
@app.get("/login")
async def login(request: Request):
    # state·nonce·PKCE(S256) 를 만들어 세션에 두고 IAM 인가 주소로 보낸다
    return await oauth.iam.authorize_redirect(request, f"{APP_URL}/callback")


@app.get("/callback")
async def callback(request: Request):
    try:
        # state 확인 → code 교환(code_verifier 포함) → ID 토큰 검증(JWKS 서명, iss, aud, exp, nonce)
        token = await oauth.iam.authorize_access_token(request)
    except OAuthError as e:
        return JSONResponse({"error": e.error, "description": e.description}, status_code=400)
    claims = token["userinfo"]
    user = link_account(claims)
    if not user["active"]:
        return JSONResponse({"error": "local_user_disabled"}, status_code=403)

    session = request.session
    session.clear()
    session.update(
        user={"sub": claims["sub"], "name": claims.get("name"), "empNo": claims.get("emp_no"),
              "roles": claims.get("roles", []), "localUserId": user["id"]},
        sid=claims.get("sid"),
        id_token=token["id_token"],
    )
    request.scope["rotate_session"] = True  # 로그인하면 세션 ID 를 새로 발급 (세션 고정 방지)
    return RedirectResponse("/me", status_code=302)


@app.get("/me")
async def me(request: Request):
    user = request.session.get("user")
    if not user:
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    return dict(user, sid=request.session.get("sid"))


@app.get("/logout")
async def logout(request: Request):
    id_token = request.session.get("id_token")
    request.session.clear()
    if not id_token:
        return {"loggedOut": True}
    return await oauth.iam.logout_redirect(request, id_token_hint=id_token)


# ── back-channel 로그아웃 ──────────────────────────────────────────────
async def verify_logout_token(value: str) -> dict:
    registry = JWSRegistry(algorithms=["RS256"], strict_check_header=False)
    try:
        token = jwt.decode(value, KeySet.import_key_set(await oauth.iam.fetch_jwk_set()), registry=registry)
    except InvalidKeyIdError:  # IAM 이 키를 바꿨으면 JWKS 를 다시 받는다
        token = jwt.decode(value, KeySet.import_key_set(await oauth.iam.fetch_jwk_set(force=True)), registry=registry)
    if token.header.get("typ") != "logout+jwt":
        raise ValueError("typ 이 logout+jwt 가 아님")
    jwt.JWTClaimsRegistry(
        leeway=60,
        iss={"essential": True, "value": ISSUER},
        aud={"essential": True, "value": CLIENT_ID},
        iat={"essential": True},
        exp={"essential": True},
    ).validate(token.claims)
    claims = token.claims
    if BACKCHANNEL_EVENT not in (claims.get("events") or {}):
        raise ValueError("events 에 back-channel 로그아웃이 없음")
    if "nonce" in claims:
        raise ValueError("nonce 가 있으면 안 됨")
    if not claims.get("sub") and not claims.get("sid"):
        raise ValueError("sub·sid 가 모두 없음")
    return claims


@app.post("/backchannel-logout")
async def backchannel_logout(request: Request):
    form = await request.form()
    try:
        claims = await verify_logout_token(str(form.get("logout_token", "")))
    except (JoseError, ValueError) as e:
        return JSONResponse({"error": "invalid_logout_token", "description": str(e)}, status_code=400)
    if claims.get("sid"):
        db.execute("delete from app_session where iam_sid = ?", (claims["sid"],))
    else:
        db.execute("delete from app_session where sub = ?", (claims["sub"],))
    return Response(status_code=200, headers={"Cache-Control": "no-store"})


# ── 웹훅 ───────────────────────────────────────────────────────────────
@app.post("/webhooks/iam")
async def webhook(request: Request):
    raw = await request.body()  # 다시 직렬화하지 않고 받은 바이트 그대로 서명을 검증한다
    timestamp = request.headers.get("X-Didrakon-Timestamp", "")
    signature = request.headers.get("X-Didrakon-Signature", "")
    expected = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), timestamp.encode() + b"." + raw, hashlib.sha256).hexdigest()
    if not WEBHOOK_SECRET or not hmac.compare_digest(expected, signature):
        return JSONResponse({"error": "bad_signature"}, status_code=401)
    if not timestamp.isdigit() or abs(time.time() - int(timestamp)) > 300:
        return JSONResponse({"error": "stale_timestamp"}, status_code=401)

    delivery = request.headers.get("X-Didrakon-Delivery", "")
    try:
        db.execute("insert into webhook_delivery (id, received_at) values (?, ?)", (delivery, int(time.time())))
    except sqlite3.IntegrityError:
        return {"duplicate": True}  # 이미 처리한 전달

    event = json.loads(raw)
    data = event.get("data") or {}
    if event.get("type") == "user.status_changed" and data.get("status") == "RETIRED":
        sub = str(data["subjectId"])  # 본문의 subjectId 는 숫자, 토큰의 sub 는 문자열
        db.execute("update local_user set active = 0 where iam_subject_id = ?", (sub,))
        db.execute("delete from app_session where sub = ?", (sub,))
    return {"ok": True}
