# 보안 구조

[README](../README.md) 로 돌아가기 · 관련 문서: [구조](architecture.md) · [API](api.md) · [관리 콘솔](admin-console.md) · 취약점 신고: [SECURITY.md](../SECURITY.md)

## 경로별 보안 체인

### 1. 로그인·인가 서버 (Spring Authorization Server)

- 경로: `/oauth2/**`, `/.well-known/**`, `/userinfo`, `/connect/logout` 등
- 인증: 클라이언트 인증, 로그인 세션

### 2. 관리·권한 판정 API (리소스 서버, 세션 없음)

- 경로: `/api/**`
- 받는 자격 증명
  - 사람의 토큰: 관리 콘솔(`iam-admin`)에 발급된 접근 토큰만. 다른 연동 시스템이 받은 토큰과 ID 토큰은 거부한다.
  - 시스템 간 토큰(client credentials): scope 를 정한 API(권한 판정 `iam.authz.check`, 인사 연동 `iam.hr.sync`)에서만 통한다. 사람이 없는 토큰이라 그 밖의 관리 API 는 403(`SUBJECT_REQUIRED`)이다.
  - `X-API-Key` (API 키): 키 주인(서비스 계정 등)의 권한으로 판정한다
- 인가
  - `@RequiresPermission`: IAM 자신의 PDP 로 판정한다. `orgOf` 로 대상 사용자·조직·소속·세션의 조직을 함께 넘긴다.
  - `@SelfService`: 본인 일만, 사용 중인 계정만.
  - 둘 다 없는 핸들러는 거부한다.

### 3. 로그인 화면·내 계정 (로그인 세션)

- `/login`, `/login/mfa`, `/login/password`, `/login/forgot`, `/logout`
  - 폼 로그인 + 인증 앱(TOTP)
  - 만료·초기화된 비밀번호는 바꾼 뒤 다시 로그인
  - 비밀번호를 잊었으면 인증 앱 코드로 셀프 재설정 (잠금도 풀림)
- `/login/webauthn`, `/webauthn/**`, `/account/passkeys`
  - 패스키 로그인, 패스키 등록·관리 화면
  - 등록·삭제는 2단계 인증을 거친 로그인만
- `/`, `/account/sessions/revoke-others` — IAM 홈(내 계정)
  - 내 앱 바로가기(앱 시작 주소를 둔 켜진 클라이언트), 계정 보안 바로가기
  - 로그인된 기기, 다른 기기 모두 로그아웃, 최근 로그인 기록 10건
  - 이미 로그인한 사람이 `/login` 을 직접 열면 여기로 온다

## 토큰

- `sub` 는 subject ID, `amr` 은 인증 방법(RFC 8176)이다.
  - 비밀번호 `[pwd]`
  - 비밀번호 + 인증 앱 `[pwd, otp]`
  - 패스키 `[hwk, user]`
- 사용자 토큰에는 `name`, `user_kind`(`EMPLOYEE`·`EXTERNAL`), `emp_no`(임직원만), `primary_org_id`, `company_org_id`, `roles` 도 들어간다.
- 접근 토큰 수명은 10분이다. 그동안 바뀐 값은 반영되지 않으므로 토큰 claim 은 메뉴 노출 같은 거친 판단에만 쓰고, 세밀한 판단은 `POST /api/v1/authz/check` 로 한다.
- refresh token 은 8시간이고 쓸 때마다 새로 바뀐다. 공개 클라이언트(public client)에는 주지 않는다.

## 세션과 회수

- 브라우저 로그인 세션(HTTP 세션)은 DB 에 저장한다 (Spring Session JDBC, `SPRING_SESSION`·`SPRING_SESSION_ATTRIBUTES`). 서버를 다시 띄우거나 여러 대로 운영해도 로그인이 유지된다.
- 30분 쓰지 않으면 끝나고, 로그인 세션 자체는 8시간이면 끝난다 (`iam.authn.session-timeout`).
  - 그 세션에서 받은 refresh token 도 세션이 끝나면 새 토큰을 받지 못한다 (`invalid_grant`).
  - 브라우저 로그인에서 나온 인가가 로그인 세션과의 연결을 잃으면(로그아웃과 refresh 가 겹친 경우 등) refresh 를 거부한다.
- 세션에 넣는 값은 직렬화할 수 있어야 한다. 로그인 실패 예외에서 입력한 비밀번호는 지운 뒤 저장한다.
- 세션 쿠키는 `JSESSIONID`, HttpOnly, SameSite=Lax 이다. 운영 프로필은 Secure 를 늘 붙인다 (`iam.authn.secure-session-cookie`).
- 로그인·인가 서버가 RP 로그아웃의 sid 확인에 쓰는 세션 목록도 DB 세션을 본다 (`SpringSessionBackedSessionRegistry`). 여러 대로 운영해도 같다.
- 토큰은 발급될 때 로그인 세션과 연결된다. 그래서 아래처럼 함께 회수된다.
  - 로그아웃·세션 종료 → 그 세션의 refresh token
  - 사용 중지·퇴사 → 그 사람의 모든 토큰·세션·API 키
  - 비밀번호 변경(본인·셀프 재설정·관리자 초기화) → 모든 세션·토큰
  - 관리자의 2단계 인증 초기화(인증 앱·패스키) → 모든 세션·토큰 (잃어버린 수단으로 연 세션을 남기지 않게)
  - SSO 클라이언트 끄기 → 그 클라이언트에 발급한 모든 토큰
  - 접근 토큰(JWT)은 만료까지 남지만, PDP 가 사용 중이 아닌 사용자를 거부한다.
- 토큰을 회수하면 back-channel 로그아웃 주소를 등록한 연동 시스템에 서명한 로그아웃 토큰(`typ: logout+jwt`)을 커밋 뒤 보낸다.
  - 로그인 세션 하나가 끝났으면 ID 토큰과 같은 `sid` 를 넣어 그 세션만 끝내게 한다.
  - 사용자 단위(사용 중지·잠금·퇴사)면 `sub` 로 그 사람의 세션을 모두 끝내게 한다.
- 토큰 검사(`/oauth2/introspect`)는 그 토큰을 받은 클라이언트만 할 수 있다. 다른 클라이언트의 토큰은 비활성(`active: false`)으로 답한다. 다른 시스템의 JWT 는 JWKS 로 검증한다.

## 로그인 보호

**호출 수 제한** (IP 별, 1분)

- 로그인 20, 토큰 120, 권한 판정 6000, 그 밖의 API 600 (`iam.rate-limit.*`)
- 기본은 서버별 메모리 카운터다. 여러 대로 운영하면 `iam.rate-limit.store: jdbc` 로 로그인·토큰 경로를 DB 에서 함께 센다.
- 운영은 프록시가 넘긴 실제 IP 를 쓴다 (`forward-headers-strategy: native`). Tomcat 은 기본으로 사설 IP 대역 전체를 프록시로 믿어, 같은 사설망의 기기가 `X-Forwarded-For` 로 IP 를 바꿀 수 있다. 운영에서는 환경 변수 `SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES` 에 실제 로드밸런서 주소만 정규식으로 넣는다.

**로그인 위험 평가**

- DENY 는 막는다 (`/login?risk`).
- CHALLENGE·APPROVAL 은 추가 인증을 요구한다.
  - 확인된 인증 앱이 있으면 MFA 단계로 보낸다.
  - 없으면 막는다 (`/login?challenge`, 실패 횟수는 그대로). `iam.risk.block-challenge-without-mfa: false` 면 기록만 하고 들여보낸다.
- 패스키 로그인은 그 자체로 추가 인증을 충족한 것으로 보고 위험 신호만 기록한다. DENY 는 패스키도 막는다.
- 해외 IP 신호(`FOREIGN_IP`)는 국가 정보가 있을 때만 잡힌다.
  - `iam.risk.geoip-database`: MaxMind GeoLite2/GeoIP2 Country `.mmdb` 경로 (환경 변수 `IAM_GEOIP_DATABASE`)
  - `iam.risk.ip-country-overrides`: CIDR → 국가 코드 (DB 보다 먼저 본다)
  - 사설·루프백 주소와 찾지 못한 주소는 신호를 만들지 않는다.

## 2단계 인증과 패스키

**패스키 로그인** (WebAuthn, 피싱 방지·비밀번호 없는 로그인)

- 로그인 화면의 `패스키로 로그인` 이 `/webauthn/authenticate/options` → `/login/webauthn` 을 부른다.
- 사용자 확인(생체·PIN)을 필수로 요구하므로 패스키 로그인은 MFA 다. MFA 필수 클라이언트와 관리 API MFA 정책을 통과하고 인증 앱 코드를 다시 묻지 않는다.
- 위험 평가·로그인 세션·감사는 비밀번호 로그인과 같고, 비밀번호 실패 횟수는 건드리지 않는다.
- 사용 안 함·퇴사·잠김 계정, 비밀번호·코드 실패로 일시 잠긴 계정은 막는다 (`/login?unavailable`).
- 2단계 인증 수단이 패스키뿐인 사람은 비밀번호만으로 로그인할 수 없고 패스키로 로그인해야 한다 (`/login?passkey-required`, 실패 횟수는 그대로). 패스키를 잃어버리면 관리자가 초기화한다.

**패스키 등록·삭제**

- IAM 화면 `/account/passkeys` 에서 하고, 2단계 인증(인증 앱 또는 패스키)을 거친 로그인만 할 수 있다. 비밀번호만 훔친 사람이 패스키를 심지 못하게 한다.
- 비밀번호로만 로그인했고 인증 앱이 있으면 코드를 받은 뒤 돌아온다. 로그인 전에 열었으면 로그인 뒤 이 화면으로 돌아온다.
- 등록·삭제는 감사(`PASSKEY_ADD`·`PASSKEY_REMOVE`)에 남는다. WebAuthn 사용자 이름은 subject ID 다.

**인증 수단 변경 API** (`/api/v1/me/mfa/**`, `DELETE /api/v1/me/passkeys/{id}`)

- 로그인한 본인 토큰만 쓴다. API 키는 403.
- 이미 인증 앱이나 패스키가 있으면 MFA(`otp`) 또는 패스키(`hwk`)로 로그인한 토큰이어야 한다 (아니면 401 `MFA_REQUIRED`).
- 첫 등록만 비밀번호 로그인으로 할 수 있다. 이 수단으로 비밀번호 재설정과 로그인을 하기 때문이다.

## 관리자 보호

**관리자가 정한 비밀번호**

- 사용자 만들기, 로그인 계정 만들기, 비밀번호 초기화로 관리자가 정한 비밀번호는 다음 로그인에서 본인이 바꿔야 한다. 관리자가 그 비밀번호를 계속 알고 쓰지 못하게 한다.

**관리 API MFA 정책** (`IAM_ADMIN_API_MFA`)

- 관리 역할로 관리 API 를 쓰려면 MFA(`otp`) 또는 패스키(`hwk`) 로그인이 필요하다.
- 콘솔·API 로 끄거나, 대상·규칙을 바꾸거나, 예외를 둘 수 없다 (409). 켜고 끄기는 설정(`iam.bootstrap.require-mfa-for-admin`)으로 한다.
- 다른 정책의 예외 추가는 감사(`ADD_EXCEPTION`)에 남는다.

**초기 구성**

- 기동할 때 `IamBootstrap` 이 관리 콘솔 클라이언트(`iam-admin`), IAM 자체 리소스·권한, 역할(`IAM_ADMIN`, `IAM_AUDITOR`, `IAM_ORG_ADMIN`, `IAM_AUTHZ_CLIENT`, `IAM_HR_SYNC`), 관리 API MFA 정책을 만든다. 여러 번 실행해도 결과가 같다.

**조직 단위 관리자** (`IAM_ORG_ADMIN`, ORGANIZATION 범위)

- 그 조직(하위 포함) 안의 사람·소속·조직·세션만 관리한다. 목록도 범위 안만 보인다.
- 역할·정책 등 전체 관리자 전용 API 는 403 이다. 역할을 줄 수 없다.
- 다른 관리자는 바꿀 수 없다. 승인된 JIT·시작 전 위임처럼 곧 관리 역할을 받을 사람도 마찬가지다.
- 관리 콘솔 권한이 있는 역할은 조직·그룹 역할 규칙으로 줄 수 없다. 소속을 바꿔 관리 역할을 얻을 수 없다.
- 관리자의 접근 재검토는 조직장이 아니라 재검토 관리자가 한다.
- 자세한 규칙: [erd-v2.md](erd-v2.md) "조직 단위 관리 규칙"

**권한 위임·비상 접근**

- 관리 권한이 있는 역할을 위임하려면 MFA 로그인 토큰이어야 한다. API 키로는 위임할 수 없다.
- 관리 콘솔 권한이 있는 역할의 비상 접근 정책은 `승인 후 시작` 만 된다. 승인 없이 시작하는 정책의 역할에는 콘솔 권한을 더할 수 없다.
- 관리 콘솔 권한이 있는 역할의 JIT·비상 접근 요청은 서로 다른 승인자 2명이 승인해야 한다 (`iam.governance.console-role-approvals`, 관리자가 한 명뿐이면 1). 승인·반려는 요청 행을 잠가 하나씩 처리하고, 사용 중인 사람의 요청만 승인한다.

**퇴사**

- 퇴사하면 지금 가진 역할과 앞으로 시작할 역할(승인된 JIT·시작 전 위임)을 모두 회수하고, 처리 중인 권한 요청을 취소한다.

**이전 데이터 점검**

- 기동할 때, 지금 규칙으로는 만들 수 없지만 이전 버전에서 만들었을 수 있는 데이터를 찾아 경고 로그(`이전 데이터 점검`)로 알린다: 관리 API MFA 정책 예외, 관리 콘솔 역할을 주는 조직·그룹 규칙과 그 할당, 승인 없이 관리 역할을 주는 비상 접근 정책. 데이터는 바꾸지 않는다.

## 사용자 구분

- 내부 임직원(`EMPLOYEE`): 사번 필수
- 외부 사용자(`EXTERNAL`, 예: B2B 고객사 사용자): 사번 없이 이메일로 식별하고 고객사 조직에 소속한다. HR 연동 대상이 아니다.
- ABAC 규칙에서는 SUBJECT `userKind` 로 구분한다.

## 다른 시스템의 인증

- 권한 판정 `POST /api/v1/authz/check`: `iam.authz.check` scope 를 가진 client credentials 토큰, 또는 `IAM_AUTHZ_CLIENT` 역할 서비스 계정의 API 키
- 인사 연동 `POST /api/v1/hr/sync`: `iam.hr.sync` scope 를 가진 client credentials 토큰, 또는 `IAM_HR_SYNC` 역할 서비스 계정의 API 키 (규칙: [erd-v2.md](erd-v2.md) "HR 연동 규칙")
