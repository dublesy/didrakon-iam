# API

[README](../README.md) 로 돌아가기 · 관련 문서: [보안](security.md) · [데이터 모델과 규칙](erd-v2.md) · [다른 시스템 연동](integration/README.md)

모든 경로는 `/api/v1` 아래에 있다. 아래에서는 `/api/v1` 을 줄여 쓴다.

## 공통

- 응답 형식: `{"success", "data", "error": {"code", "message", "fields"}}`
- 요청에 `X-Trace-Id` 를 넣으면 감사 기록에 남고 응답 헤더로 돌아온다.
- 인증: 관리 콘솔 토큰, 시스템 간 토큰(client credentials), `X-API-Key` ([보안 구조](security.md#2-관리권한-판정-api-리소스-서버-세션-없음))
- 기준 데이터는 지우지 않는다. `PUT /{대상}/{id}` 로 고치고 `/{id}/activate`·`/{id}/deactivate` 로 켜고 끈다.
  - 대상: `users`, `organizations`, `groups`, `roles`, `resources`, `permissions`, `scopes`, `policies`, `role-conflicts`, `clients`
- 연결(역할의 권한, 예외)은 기간을 끝내 회수한다: `DELETE /role-permissions/{id}`, `/policy-exceptions/{id}`, `/role-conflict-exceptions/{id}`

## 사람과 조직

**사용자** `/users`

- `GET /users?q=&kind=` — 이름·사번·이메일 검색, `kind` 는 `EMPLOYEE`·`EXTERNAL`
- `POST /users` — 만들기. `userKind`·`primaryOrgId` 로 주 소속까지. `loginId`·`password` 를 함께 주면 로그인 계정도 만든다 (다음 로그인에 비밀번호 변경 강제)
- `GET /users/{id}`, `GET /subjects/names`, `GET /subjects/{id}/memberships`
- `POST /users/{id}/retire` — 퇴사 (미래 날짜면 예약), `DELETE` 로 예약 취소
- `POST /users/lookup` — 연동 시스템 계정 연결용: 사번·이메일 목록 → subject ID (전체 범위 조회 권한만)

**로그인 계정**

- `GET /users/{id}/credential` — 로그인 ID·잠금·비밀번호 상태
- `POST /users/{id}/login-account` — 로그인 계정이 없는 사람에게 만들기 (다음 로그인에 비밀번호 변경 강제)
- `POST /users/{id}/password` — 관리자 초기화 (다음 로그인에 변경 강제)
- `POST /users/{id}/unlock` — 잠금 해제 (비밀번호 유지)

**조직·소속·그룹**

- `/organizations` — 목록·만들기, `GET /organizations/{id}`, `/{id}/members`, `/{id}/roles`, `POST /{id}/move`(상위 조직 바꾸기)
- `/memberships` — 소속 추가, `PUT /memberships/{id}`(직위·직급·조직 관리자), `DELETE /memberships/{id}`
- `POST /subjects/{id}/primary-membership` — 주 소속 옮기기(전적·전보, 전적이면 권한 정리)
- `/groups` — 목록·만들기, `/{id}/members`(추가·빼기), `/{id}/roles`

## 권한

- `/resources`, `/roles`, `/permissions`, `/scopes` — 목록·만들기, `GET /roles/{id}`
- `POST /roles/{id}/permissions` — 역할에 권한 담기
- `/assignments` — 직접 할당 만들기, `PUT /assignments/{id}`(만료일 변경), `DELETE /assignments/{id}`
- `GET /subjects/{id}/assignments`
- `/organization-roles`, `/group-roles` — 조직·그룹 역할 규칙 만들기·끝내기

## 정책

- `/policies` — 목록·만들기, `GET /policies/{id}`
- `PUT /policies/{id}/targets` — 대상 바꾸기 (다음 판정부터 적용)
- `POST /policies/{id}/versions`, `POST /policy-versions/{id}/activate` — ABAC 규칙 버전
- `POST /policies/{id}/exceptions` — 예외 추가 (관리 API MFA 정책에는 불가)

## 권한 판정 (다른 시스템이 호출)

- `POST /authz/check` — subject·리소스(`resourceId` 또는 `clientCode`+`resourceKey`)·action·조직·문맥으로 판정 결과와 근거를 돌려준다. 거부도 200 응답의 `decision` 으로 알린다

## 거버넌스

**승인**

- `GET /access-requests/pending`, `GET /access-requests/history`(처리 시각 `closedAt` 포함)
- `POST /access-requests/{id}/approve`, `/reject`

**직무 분리**

- `/role-conflicts` — 목록·만들기, `PUT` 으로 심각도·설명 변경 (역할 쌍은 그대로)
- `POST /role-conflicts/{id}/exceptions`

**비상 접근**

- `/break-glass-policies` — 목록·추가·수정·켜기/끄기
  - `eligibleGroupId` 를 정하면 그 그룹 구성원만 시작할 수 있고, 비우면 사용 중인 사람 누구나
  - 관리 콘솔 권한이 있는 역할은 `승인 후 시작` 만 된다
  - `GET /break-glass-policies/group-options` — 그룹 선택지
- `GET /break-glass-sessions`, `POST /break-glass-sessions/{id}/end`(관리자 종료)

**위임**

- `GET /delegations`, `POST /delegations/{id}/revoke`(관리자 회수)

**접근 재검토**

- `/access-reviews` — 목록·시작
- `GET /access-reviews/{id}?decision=` — 항목
- `POST /access-reviews/{id}/close` — 마감
- `GET /access-reviews/{id}/export` — 증적 CSV (UTF-8 BOM)
- `POST /access-review-items/{id}/decide` — 관리자 결정

## 클라이언트·세션·인증 수단

**SSO 클라이언트** `/clients`

- 목록·등록. 리다이렉트·로그아웃 뒤 주소·scope·기밀 여부 포함
  - 웹 클라이언트의 주소는 http·https 만, 모바일 앱은 사용자 정의 스킴도 받는다. `javascript:`·`data:` 같은 스킴은 받지 않는다
  - `iam.` 으로 시작하는 scope(`iam.authz.check`·`iam.hr.sync`)는 시스템 클라이언트(API·BATCH)에만 준다
  - 끄면 그 클라이언트에 발급한 토큰을 모두 회수한다
- `PUT /clients/{id}` — 주소·scope·back-channel 로그아웃 주소·Supabase 호환(`supabaseRoleClaim`) 변경. client_id 는 그대로, `iam-admin` 의 로그인 설정은 못 바꾼다
- `POST /clients/{id}/rotate-secret` — 비밀값 재발급 (응답에서 한 번만 보인다)

**세션**

- `GET /subjects/{id}/sessions`, `DELETE /subjects/{id}/sessions`(모든 세션·토큰 회수), `DELETE /sessions/{id}`

**API 키**

- `GET /subjects/{id}/api-keys`(폐기 시각 포함), `POST /subjects/{id}/api-keys`(발급), `DELETE /api-keys/{id}`(폐기)
- 발급·폐기는 감사에 키 주인을 대상자로 남긴다

**2단계 인증 (관리자)**

- `GET /subjects/{id}/mfa` — 인증 앱·패스키 목록
- `DELETE /subjects/{id}/mfa/{methodId}`, `DELETE /subjects/{id}/mfa/passkeys/{credentialId}` — 기기 분실 시 초기화

## 위험·감사·외부 연동

- `/risk-policies` — 목록·추가·수정·켜기/끄기, `GET /subjects/{id}/risk`(최근 평가와 신호)
- `GET /audit/events`, `GET /audit/role-history/{subjectId}`, `GET /audit/policy-history/{policyId}`
- `/webhooks` — 목록·추가 (서명 비밀값은 추가·교체 응답에서 한 번만)
  - `PUT /webhooks/{id}`, `/{id}/activate`·`deactivate`·`rotate-secret`·`test`
  - `GET /webhooks/{id}/deliveries`(최근 50건), `POST /webhook-deliveries/{id}/redeliver`
- `POST /hr/sync?dryRun=true|false` — 인사 원본으로 입사·이동·휴직·퇴사, `reportMissing` 이면 피드에 없는 사용자 보고
- `GET /hr/sync-runs` — 최근 50건

## 본인 (`/me`)

로그인한 본인 일만 한다. 사용 중인 계정만 쓸 수 있다.

- `GET /me`, `GET /me/admin-scope`(관리 범위: 전체 여부·조직·쓸 수 있는 관리 리소스)
- `POST /me/password`
- 2단계 인증: `GET /me/mfa`, `POST /me/mfa/totp`, `POST /me/mfa/totp/{id}/confirm`, `DELETE /me/mfa/{id}`, `GET /me/passkeys`, `DELETE /me/passkeys/{id}`
- 권한 요청: `GET·POST /me/access-requests`, `POST /me/access-requests/{id}/cancel`, `GET /me/access-options`(선택지)
- 위임: `GET·POST /me/delegations`, `DELETE /me/delegations/{id}`, `GET /me/people?empNo=`(위임받을 사람 찾기)
- 비상 접근: `GET /me/break-glass-policies`, `GET /me/break-glass-sessions`, `POST /me/break-glass`, `POST /me/break-glass/{id}/end`
- 접근 재검토: `GET /me/access-reviews`, `POST /me/access-review-items/{id}/decide`
