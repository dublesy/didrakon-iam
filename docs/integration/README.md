# 시스템 연동 가이드

기존 시스템을 DIDRAKON IAM 에 붙이는 방법. 언어와 관계없이 같은 공통 부분을 여기 두고, 언어별 코드는 [스택별 빠른 시작](#스택별-빠른-시작)에, 기존 DB 계정을 IAM 사용자와 잇는 방법은 [데이터 이관 가이드](database.md)에 둔다.

IAM 은 표준 OIDC(OpenID Connect) IdP 다. HTTP 를 보내고 JWT 서명을 검증할 수 있으면 어떤 언어든 붙일 수 있다.

## 1. 연동 단계 고르기

| 단계 | 시스템이 하는 일 | 얻는 것 |
|---|---|---|
| **1. 인증(SSO)** | 자체 로그인 대신 IAM 으로 로그인, back-channel 로그아웃 받기 | 2단계 인증·패스키·위험 기반 차단·잠금, 퇴사자 로그인 차단, 로그인 감사가 IAM 한곳에 |
| **2. + 퇴사·이동 정리** | 웹훅을 받아 자체 계정·권한 정리, 하루 한 번 대사 | 퇴사·휴직·부서 이동이 시스템 권한에도 반영 |
| **3. + 역할을 IAM 으로** | 역할 할당을 IAM 에서 하고, 토큰 `roles` 나 `/api/v1/authz/check` 로 판단 | JIT·비상 권한, 승인, 직무 분리, 접근 재검토, 권한 변경 감사가 IAM 한곳에 |

처음에는 모든 시스템을 **1·2단계**로 붙이고, 개인정보·결제처럼 감사가 중요한 시스템부터 3단계로 옮기는 것을 권한다. "그 역할로 무엇을 할 수 있나"(자기 부서 건만, 금액 한도 등) 같은 업무 규칙은 3단계에서도 각 시스템에 둔다.

## 2. IAM 에 등록하기

관리 콘솔 `리소스·권한 → 클라이언트`에서 등록한다 (API 는 `POST /api/v1/clients`).

| 항목 | 정하는 법 |
|---|---|
| 클라이언트 코드 | OAuth2 `client_id` 로 쓴다. 바꿀 수 없으니 시스템을 나타내는 짧은 영문 (`erp`, `groupware`). 숫자만으로는 만들 수 없다 (사용자 ID 와 헷갈리지 않게) |
| 유형 | 사람이 로그인하는 웹·모바일은 `WEB`·`MOBILE`, 서버 간 호출은 `API`·`BATCH` |
| 기밀 클라이언트 | 서버에서 토큰을 교환하면 켠다 (비밀값 발급). 브라우저·앱만 있는 SPA·모바일은 끄고 PKCE 를 쓴다 |
| 리다이렉트 URI | 로그인 뒤 돌아올 주소. **정확히 일치**해야 한다 (`https://erp.example.com/callback`) |
| 로그아웃 후 주소 | IAM 로그아웃 뒤 돌아올 주소 (`post_logout_redirect_uri`). 이것도 등록한 값과 같아야 한다 |
| 로그아웃 알림 주소 | back-channel 로그아웃 토큰을 받을 주소 (`https://erp.example.com/backchannel-logout`) |
| MFA 필수 | 개인정보·결제 시스템은 켠다. 켜면 인증 앱(TOTP) 또는 패스키로 로그인한 경우(`amr` 에 `otp` 또는 `hwk`)만 토큰을 받는다. 비밀번호로만 로그인했으면 인증 앱 코드를 더 묻고, 인증 앱을 등록하지 않은 사용자는 거부한다 |
| Supabase 호환 | Supabase 를 쓰는 시스템만 켠다. 토큰에 `role: "authenticated"` 가 들어간다 ([데이터 이관 가이드](database.md#supabase)) |
| 앱 시작 주소 | (선택, `WEB`·`MOBILE`) 넣으면 IAM 홈의 내 앱 목록에 나온다. http(s) 절대 주소 |

- 비밀값은 **등록할 때 한 번만** 보인다. 시스템의 비밀 저장소(환경변수, Vault 등)에 넣고 코드나 저장소에 두지 않는다.
- 등록한 뒤에도 이름, MFA 필수, 로그아웃 알림 주소, Supabase 호환, 앱 시작 주소, 리다이렉트 URI·로그아웃 후 주소·scope 를 고칠 수 있다 (`PUT /api/v1/clients/{id}`). 클라이언트 코드·유형·기밀 여부는 바꿀 수 없다.
- 비밀값이 새었거나 주기적으로 바꿀 때는 **비밀값 재발급**(`POST /api/v1/clients/{id}/rotate-secret`)을 한다. 새 비밀값은 이때 한 번만 보이고, 이전 비밀값은 바로 쓸 수 없다 (이미 발급된 토큰은 만료까지 유효). 비밀값 없는 클라이언트는 재발급할 수 없다.
- 웹훅은 `운영 → 웹훅`에서 따로 구독한다 (2단계).

## 3. 로그인 흐름

모든 주소는 discovery 문서 하나에서 읽는다. 라이브러리에 issuer 만 넣으면 된다.

```
{IAM}/.well-known/openid-configuration
```

| 주소 | 경로 |
|---|---|
| 인가 | `/oauth2/authorize` |
| 토큰 | `/oauth2/token` (기밀 클라이언트는 `client_secret_basic`) |
| 공개키 | `/oauth2/jwks` (RS256, `kid` 있음) |
| 사용자 정보 | `/userinfo` |
| 로그아웃 | `/connect/logout` (`id_token_hint`, `post_logout_redirect_uri`) |
| 토큰 회수 | `/oauth2/revoke` |

흐름은 **Authorization Code + PKCE** 다. 기밀 클라이언트도 PKCE 를 함께 쓰는 것을 권한다.

1. `/login`: `state`, `nonce`, PKCE `code_verifier` 를 만들어 세션에 두고 IAM 인가 주소로 보낸다 (`scope=openid profile`)
2. IAM 이 로그인을 처리한다 (2단계 인증·위험 평가 포함). 2단계 인증 수단이 패스키뿐인 사용자는 비밀번호로는 들어갈 수 없고 패스키로 로그인한다
3. `/callback`: `state` 를 확인하고 `code` 를 토큰으로 바꾼 뒤 **ID 토큰을 검증**한다
   - 서명(JWKS), `iss` = IAM 주소, `aud` 에 내 `client_id`, `exp`, `nonce`
4. `sub` 로 로컬 계정을 찾아([계정 연결](#5-계정-연결)) 세션을 만든다

### 토큰에 들어 있는 것

| claim | 뜻 | 예 |
|---|---|---|
| `sub` | **IAM subject ID**. 계정 연결의 키. 바뀌지 않는다 | `"1042"` |
| `name` | 이름 | `"김하늘"` |
| `user_kind` | `EMPLOYEE`(임직원)·`EXTERNAL`(외부, 예: 고객사) | |
| `emp_no` | 사번 (임직원만) | `"D-001"` |
| `primary_org_id`, `company_org_id` | 주 소속 조직·소속 법인 ID (문자열) | |
| `roles` | IAM 역할 코드 목록 | `["HR_MANAGER"]` |
| `amr` | 인증 방법: `pwd`, `otp`(인증 앱), `hwk`+`user`(패스키) | `["pwd","otp"]` |
| `sid` | IAM 로그인 세션을 가리키는 값 (ID 토큰). back-channel 로그아웃이 이 값을 보낸다 | |
| `role` | Supabase 호환을 켠 클라이언트만 `"authenticated"` | |

- 위 IAM claim 은 ID 토큰과 접근 토큰에서 읽는다. `/userinfo` 는 `sub` 와 `name` 같은 표준 claim 만 돌려주고 `emp_no`·`roles` 등은 주지 않는다.
- `name`·`user_kind`·`emp_no`·`primary_org_id`·`company_org_id`·`roles` 는 사용자 토큰(접근·ID 토큰)에만 들어간다. 소속이 없으면 `primary_org_id`·`company_org_id` 가 없다. client credentials 토큰은 `sub` 가 클라이언트 코드이고 이 값들이 없다.
- 접근 토큰은 **10분**, refresh token 은 8시간이고 refresh 할 때마다 새로 받는다 (예전 것은 쓸 수 없다).
- refresh token 은 그것을 낳은 **IAM 로그인 세션이 살아 있을 때만** 쓸 수 있다. 로그인 세션이 끝나면(로그인 후 8시간, 로그아웃, 관리자 세션 종료, 비밀번호 변경, 사용 중지·잠금·퇴사) refresh 는 `invalid_grant` 로 실패하니 다시 로그인시킨다.
- 비밀값 없는 클라이언트(PKCE 만 쓰는 SPA·모바일)는 refresh token 을 받지 않는다. 접근 토큰이 끝나면 다시 인가 요청을 보낸다 (IAM 로그인 세션이 살아 있으면 로그인 화면 없이 돌아온다).
- 토큰 안의 값은 발급 시점 값이다. 역할·소속이 바뀌어도 토큰 수명 동안은 그대로이므로 메뉴 노출 같은 거친 판단에만 쓰고, 민감한 동작은 [권한 판정 API](#8-권한-판정-api-3단계)로 그때그때 묻는다.

## 4. 로그아웃

- **앱에서 로그아웃**: 앱 세션을 지운 뒤 `/connect/logout?id_token_hint=...&post_logout_redirect_uri=...` 로 보내 IAM 로그인 세션까지 끝낸다. `post_logout_redirect_uri` 는 등록한 값이어야 한다.
- **back-channel 로그아웃 받기 (필수)**: IAM 에서 로그아웃하거나 관리자가 세션을 끊거나, 사용자를 사용 중지·잠금·퇴사시키거나 비밀번호가 바뀌면(본인 변경·셀프 재설정·관리자 초기화) IAM 이 등록한 주소로 `POST` 한다. 이때 IAM 은 그 사용자의 세션과 토큰도 함께 회수한다.
  - 본문: `application/x-www-form-urlencoded` 의 `logout_token`
  - 검증: 서명(JWKS), 헤더 `typ: logout+jwt`, `iss`, `aud` 에 내 `client_id`, `iat`·`exp`, `events` 에 `http://schemas.openid.net/event/backchannel-logout`, `nonce` 가 **없어야** 한다
  - `sid` 가 있으면 그 로그인 세션 하나(로그인할 때 받은 ID 토큰의 `sid` 와 같은 값)만, 없으면 `sub` 의 세션을 **모두** 끝낸다
    - `sid` 가 오는 경우: 로그아웃, 관리자가 세션 하나를 끊음, 본인이 "다른 기기에서 모두 로그아웃"
    - `sub` 만 오는 경우: 사용 중지·잠금·퇴사, 비밀번호 변경, 관리자의 "모든 세션 끊기"
  - 처리했으면 `200`, 검증에 실패하면 `400`
  - 세션을 서버(DB·Redis·메모리)에 두어야 남의 요청으로 끝낼 수 있다. 세션 전체를 쿠키에만 담는 방식은 back-channel 로그아웃을 받을 수 없다

## 5. 계정 연결

로컬 사용자 테이블에 **`iam_subject_id`** 컬럼을 두고 IAM `sub` 를 저장한다. 이후 로그인은 이 값으로만 찾는다.

| 방식 | 언제 | 방법 |
|---|---|---|
| **미리 일괄 연결 (권장)** | 기존 사용자가 있는 시스템 | 전환 전에 사번·이메일 목록으로 [계정 연결 조회 API](database.md#계정-연결-조회-api)를 불러 `iam_subject_id` 를 채운다 |
| 첫 로그인 때 연결 | 사번처럼 확실한 키가 있을 때만 | `iam_subject_id` 로 못 찾으면 토큰의 `emp_no` 로 찾아 연결하고 저장한다 |
| 첫 로그인 때 생성 (JIT) | 계정을 미리 만들 필요가 없는 시스템 | 못 찾으면 기본 권한만 가진 계정을 만든다 |

- **이메일로 자동 연결하지 않는다.** 이메일은 바뀌고, 임직원과 외부 사용자가 같은 이메일을 쓸 수 있어 남의 계정에 연결될 수 있다.
- 공용 계정·배치 계정은 사람이 아니므로 IAM 사용자로 옮기지 않고 서비스 계정(client credentials, API 키)으로 바꾼다.
- 자세한 SQL·절차는 [데이터 이관 가이드](database.md).

## 6. 웹훅 받기 (2단계)

IAM 이 변경을 시스템에 알린다. `운영 → 웹훅`에서 받을 주소와 이벤트를 등록한다.

```
POST /webhooks/iam
Content-Type: application/json
X-Didrakon-Event: user.status_changed
X-Didrakon-Delivery: 1234            ← 전달 ID (중복 거르기용)
X-Didrakon-Timestamp: 1793797751     ← 보낸 시각 (epoch 초)
X-Didrakon-Signature: sha256=<hex>

{"id":"<이벤트 UUID>","type":"user.status_changed","occurredAt":"...","data":{"subjectId":1042,"status":"RETIRED"}}
```

1. **서명 검증**: `hex(HMAC-SHA256(비밀값, 타임스탬프 + "." + 받은 본문 그대로))` 를 계산해 `sha256=` 뒤 값과 **상수 시간 비교**한다. 본문을 JSON 으로 다시 직렬화하지 말고 받은 바이트 그대로 쓴다
2. **시각 확인**: 타임스탬프가 5분보다 오래됐으면 `401` (재전송 공격 방지)
3. **중복 거르기**: 같은 전달이 두 번 올 수 있다. `X-Didrakon-Delivery` 를 저장해 두고 이미 처리했으면 `200` 만 돌려준다
4. **빨리 답하기**: 5초 안에 `2xx` 를 줘야 성공이다. 오래 걸리는 정리는 큐에 넣고 먼저 답한다
5. 실패하면 IAM 이 30초·2분·10분·1시간·6시간 뒤 다시 보내고 여섯 번째에 멈춘다. 같은 구독의 뒤 전달은 앞 전달이 끝날 때까지 기다린다 (순서 보장)

### 이벤트별 처리 규칙 (권장)

| 이벤트 | data | 시스템이 할 일 |
|---|---|---|
| `user.status_changed` | `subjectId`, `status` | `RETIRED`: 계정 끄고 **권한 모두 회수**. `DISABLED`·`LOCKED`: 계정 정지(권한 보존). `ACTIVE`: 정지 해제 |
| `membership.changed` | `subjectId`, `change`(`JOINED`·`LEFT`·`UPDATED`·`TRANSFERRED`), 조직 ID (`orgId`, `TRANSFERRED` 면 `fromOrgId`·`toOrgId`) | `TRANSFERRED`(부서 이동): 기본 권한만 남기고 회수하거나 새 부서 관리자 확인 대기로 표시 |
| `group_membership.changed` | `groupId`, `subjectId`, `change` | 그룹 단위로 권한을 주는 시스템이면 해당 사용자 재계산 |
| `organization.moved` | `orgId`, `subtreeOrgIds` | 조직 단위로 권한을 주는 시스템이면 해당 조직 사용자 재계산 |
| `role_assignment.changed` | `assignmentId`, `subjectId`, `roleId`, `changeType` | (3단계) 역할 캐시 무효화 |
| `access_request.changed` | `requestId`, `requestType`, `subjectId`, `roleId`, `status` | 대개 무시 (승인돼 역할이 생기면 `role_assignment.changed` 도 온다) |
| `access_review.changed` | `campaignId`, `action`, `itemCount` | 대개 무시 (회수 결정은 `role_assignment.changed` 로도 온다) |
| `user.credential_changed` | `subjectId`, `credentialType`(`PASSKEY`), `change`(`ADDED`·`REMOVED`) | 보안 민감 시스템이면 알림·재인증 요구 |
| `config.changed` | `target`, `targetId`, `action` | 대개 무시 |
| `webhook.test` | `subscriptionId` | 콘솔의 "테스트 전송"으로 그 구독에만 온다. `200` 만 돌려준다 |

본문에는 ID 와 상태 코드만 있다. 이름·연락처 같은 개인정보가 필요하면 IAM API 로 조회한다.

### 대사 작업 (필수)

웹훅은 시스템이 오래 꺼져 있으면 결국 포기(DEAD)된다. 하루 한 번 **로컬 활성 계정의 `iam_subject_id` 목록**을 IAM 사용자 상태와 비교해 IAM 에서 `ACTIVE` 가 아닌 사람을 정리한다. 상태는 관리 API(`GET /api/v1/users/{subjectId}`)나 [계정 연결 조회 API](database.md#계정-연결-조회-api)로 확인한다. 둘 다 사용자 조회 권한을 받은 서비스 계정의 API 키로 부른다 ([7. 서버 간 호출](#7-서버-간-호출-배치api)).

## 7. 서버 간 호출 (배치·API)

사람이 아닌 시스템은 `API`·`BATCH` 유형 클라이언트로 등록하고 client credentials 로 토큰을 받는다.

```
POST /oauth2/token   (Basic client_id:secret)
grant_type=client_credentials&scope=iam.authz.check
```

또는 서비스 계정 사용자에게 API 키를 발급해 `X-API-Key` 헤더로 부른다 (`/api/v1/subjects/{id}/api-keys`).

- **`/api` 는 관리 콘솔(`iam-admin`)에 발급된 접근 토큰, client credentials 토큰, API 키만 받는다.** 시스템이 사용자 로그인으로 받은 접근 토큰이나 ID 토큰으로 부르면 `401` 이다. 사용자 대신 부르지 말고 시스템 자격으로 부른다.
- client credentials 토큰은 사용자(subject)가 없어 scope 로 열어 둔 API 만 부를 수 있다: 권한 판정(`iam.authz.check`), HR 연동(`iam.hr.sync`). 클라이언트 등록 때 이 scope 를 넣어 둔다.
- 사용자 조회(`/api/v1/users/{subjectId}`, `/api/v1/users/lookup`)처럼 권한이 필요한 나머지 API 는 그 권한을 가진 역할을 할당한 서비스 계정의 API 키로 부른다.
- IP 당 1분 호출 한도: 로그인 20, 토큰 발급·갱신(`/oauth2/token`) 120, 권한 판정 6000, 그 밖의 `/api` 600. 넘으면 `429` 와 `Retry-After`(초)가 온다. 토큰은 만료 전까지 재사용하고 요청마다 새로 받지 않는다.

## 8. 권한 판정 API (3단계)

```
POST /api/v1/authz/check     (iam.authz.check scope 토큰 또는 IAM_AUTHZ_CLIENT 역할 API 키)
{"subjectId": 1042, "clientCode": "erp", "resourceKey": "payment", "action": "APPROVE", "context": {"amount": 3000000}}

→ {"data": {"decision": "ALLOW" | "DENY", "reason": "...", "explanation": [...], "riskScore": 20}}
```

- 거부도 `200` 의 `decision` 으로 온다. `DENY` 면 막는다.
- IAM 에 연결할 수 없을 때 기본은 **거부(fail closed)**. 화면 조회처럼 막혀도 되는 것만 짧게 캐시한다.

## 9. 전환 절차

1. **준비**: 클라이언트 등록, 리다이렉트·로그아웃 주소 확인, 코드 배포(자체 로그인은 아직 둠)
2. **일괄 연결**: [데이터 이관 가이드](database.md)대로 `iam_subject_id` 를 채우고, 못 맞춘 계정 목록을 사람이 정리
3. **병행 (예: 2주)**: 로그인 화면 기본을 IAM 으로. 자체 로그인은 비상용으로만
4. **전환**: 자체 로그인을 막고 비밀번호 해시를 폐기. 비상용 관리자 계정 하나만 남기고 사용을 감사
5. **2단계 켜기**: 웹훅 구독, 대사 작업
6. **되돌리기 계획**: 전환 직후 문제가 생기면 3단계 상태로 돌아갈 수 있게, 비밀번호 폐기는 병행 기간이 끝난 뒤에 한다

## 10. 운영 전 점검표

- [ ] ID 토큰 서명·`iss`·`aud`·`exp`·`nonce` 를 검증한다 (라이브러리 기본값이 꺼져 있지 않은지)
- [ ] `state` 와 PKCE 를 쓴다
- [ ] 리다이렉트 URI 는 https 이고 등록한 값과 정확히 같다
- [ ] 자체 비밀번호 로그인이 막혀 있다 (비상 계정 제외)
- [ ] back-channel 로그아웃을 받으면 실제로 세션이 끝난다
- [ ] refresh 가 `invalid_grant` 로 실패하면 앱 세션을 끝내고 다시 로그인시킨다
- [ ] `/api` 는 사용자 토큰이 아니라 client credentials 토큰이나 서비스 계정 API 키로 부른다
- [ ] 웹훅 서명·시각·중복을 검사하고, 퇴사 이벤트로 권한이 회수된다
- [ ] 대사 작업이 돈다
- [ ] 클라이언트 비밀값·웹훅 비밀값이 코드·저장소·로그에 없다
- [ ] 서버 시각이 NTP 로 맞춰져 있다 (토큰 `exp`·웹훅 시각 검사)

## 스택별 빠른 시작

모든 예제는 같은 기능(로그인, 계정 연결, back-channel 로그아웃, 웹훅 수신)을 구현하고, [`examples/integration/verify.py`](../../examples/integration/verify.py) 로 로컬 IAM 에 실제로 붙여 확인했다. 예제 코드는 [`examples/integration/`](../../examples/integration/) 에 있다.

| 스택 | 문서 |
|---|---|
| Spring Boot | [spring-boot.md](spring-boot.md) |
| Node.js (Express) | [express.md](express.md) |
| Next.js | [nextjs.md](nextjs.md) |
| Python (FastAPI) | [python.md](python.md) |
| Go | [go.md](go.md) |
| Rust | [rust.md](rust.md) |
| PHP | [php.md](php.md) |
| .NET (ASP.NET Core) | [dotnet.md](dotnet.md) |
| Ruby (Sinatra) | [ruby.md](ruby.md) |
| C++·코드를 고칠 수 없는 시스템 (인증 프록시) | [proxy.md](proxy.md) |
