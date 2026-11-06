# 연동 예제

[연동 가이드](../../docs/integration/README.md)의 스택별 예제 앱. 모든 예제가 같은 기능을 같은 주소로 구현하므로, 한 검증기([`verify.py`](verify.py))로 로컬 IAM 에 실제로 붙여 확인한다.

## 예제 목록

| 폴더 | 스택 | 포트 | 실행 |
|---|---|---|---|
| `spring-boot/` | Spring Boot 3 + Spring Security OAuth2 Client | 4101 | 로컬 JDK 17 |
| `express/` | Node.js + Express + openid-client | 4102 | 로컬 Node |
| `nextjs/` | Next.js (App Router) + openid-client | 4103 | 로컬 Node |
| `python/` | FastAPI + Authlib | 4104 | 로컬 Python |
| `go/` | Go + go-oidc + x/oauth2 | 4105 | 로컬 Go |
| `rust/` | Rust + axum + openidconnect | 4106 | Docker |
| `php/` | PHP + jumbojett/openid-connect-php | 4107 | Docker |
| `dotnet/` | ASP.NET Core + OpenIdConnect | 4108 | Docker |
| `ruby/` | Ruby + Sinatra + openid_connect | 4109 | Docker |
| `proxy/` | Apache + mod_auth_openidc 앞단 + C++ 앱 (코드를 고칠 수 없는 시스템) | 4110 | Docker |

## 모든 예제가 구현하는 것 (계약)

| 주소 | 하는 일 |
|---|---|
| `GET /login` | `state`·`nonce`·PKCE 를 세션에 두고 IAM `/oauth2/authorize` 로 보낸다 (`scope=openid profile`) |
| `GET /callback` | `state` 확인 → code 교환(`client_secret_basic` + `code_verifier`) → **ID 토큰 검증**(JWKS 서명, `iss`, `aud`, `exp`, `nonce`) → 계정 연결 → 서버 세션 생성 → `/me` 로 |
| `GET /me` | 로그인했으면 `200` `{"sub","name","empNo","roles","localUserId","sid"}`, 아니면 `401` |
| `GET /logout` | 앱 세션을 지우고 IAM `/connect/logout?id_token_hint=…` 로 |
| `POST /backchannel-logout` | `logout_token` 검증(서명, `typ: logout+jwt`, `iss`, `aud`, `iat`·`exp`, `events`, `nonce` 없음) → `sid` 가 있으면 그 세션만, 없으면 `sub` 의 모든 세션 종료 → `200` (실패 `400`) |
| `POST /webhooks/iam` | 받은 본문 그대로 HMAC-SHA256 서명 검증(상수 시간 비교) → 시각 5분 이내 → `X-Didrakon-Delivery` 중복 거르기 → `user.status_changed` 가 `RETIRED` 면 로컬 계정 끄고 세션 종료 → `200` (서명·시각 실패 `401`) |

**계정 연결**: 로컬 사용자 저장소에 `iam_subject_id` 를 둔다. `sub` 로 찾고, 없으면 토큰의 `emp_no` 로 찾아 연결하고, 그래도 없으면 새로 만든다(JIT). 예제는 메모리나 SQLite 에 두지만 실제 시스템은 [데이터 이관 가이드](../../docs/integration/database.md)대로 DB 컬럼을 쓴다.

**세션**: 서버에 둔다(메모리·SQLite). 세션 전체를 쿠키에만 담으면 back-channel 로그아웃으로 끝낼 수 없다.

## 실행과 검증

1. 로컬 IAM(`http://localhost:8080`)을 띄운다.
2. 관리 콘솔에서 예제마다 클라이언트를 등록한다.
   - 코드 `sample-<폴더>` (예: `sample-go`), 유형 `WEB`, 기밀
   - 리다이렉트 `http://localhost:<포트>/callback`, 로그아웃 뒤 돌아갈 주소 `http://localhost:<포트>/`, 로그아웃 알림 주소 `http://localhost:<포트>/backchannel-logout`
   - `proxy/` 만 다르다: 로그아웃 알림 주소 `http://localhost:4110/callback?logout=backchannel`, 로그아웃 뒤 돌아갈 주소 `http://localhost:4110/me`
3. `.env.local` (커밋하지 않음)에 값을 둔다.
   ```
   IAM_ISSUER=http://localhost:8080
   IAM_TEST_LOGIN_ID=...          # 시험용 사용자 (2단계 인증 없음)
   IAM_TEST_PASSWORD=...
   WEBHOOK_SECRET=whsec_...       # 예제와 검증기가 함께 쓰는 웹훅 서명 비밀값
   GO_CLIENT_ID=sample-go         # 예제마다 <폴더 대문자>_CLIENT_ID, _CLIENT_SECRET
   GO_CLIENT_SECRET=...
   ```
4. 예제 폴더의 `./run.sh` 로 띄우고 검증한다.
   ```bash
   python3 verify.py http://localhost:4105
   ```

Docker 로 띄우는 예제는 컨테이너 안에서도 IAM 주소가 `http://localhost:8080` 이어야 토큰의 `iss` 와 맞으므로, 컨테이너 안의 8080 을 호스트로 넘긴다 (각 예제 `run.sh` 참고).
