# DIDRAKON IAM — 작업 지침

범용 IAM 플랫폼. 개요·실행 방법은 [README.md](README.md), 구조는 [docs/architecture.md](docs/architecture.md), 보안은 [docs/security.md](docs/security.md), API 는 [docs/api.md](docs/api.md), 데이터 모델과 규칙은 [docs/erd-v2.md](docs/erd-v2.md), 화면 규칙은 [admin/DESIGN.md](admin/DESIGN.md) 를 먼저 읽는다. 여기에는 그 문서에 없는, 작업할 때 지켜야 할 것만 둔다.

## 구조 규칙

- 패키지는 `com.didrakon.iam.<모듈>`. 모듈 의존 방향은 [docs/architecture.md](docs/architecture.md) 의 "모듈 의존 방향"을 따르고, 역방향 의존을 만들지 않는다.
- 모듈 간 연동은 **도메인 이벤트**(같은 트랜잭션, 동기)로 한다. 발행 모듈은 구독 모듈을 모른다. 하위 모듈이 상위 모듈 기능이 필요하면 인터페이스를 두고 위에서 구현한다 (예: `RoleGrantGuard`, `UserTokenClaims`).
- audit 는 맨 끝 소비자다. 다른 모듈이 audit 에 의존하지 않는다. 감사가 필요한 변경은 이벤트를 내고 audit 에 리스너를 둔다 (기준 데이터 변경은 `AdminChangeEvent`).
- 트랜잭션은 서비스에만. 컨트롤러는 얇게, API DTO 는 `iam-app/api` 에 둔다.
- 스키마 변경은 Flyway 새 버전(`V{n}__설명.sql`)으로만. 기존 마이그레이션은 고치지 않는다. 테이블을 추가하면 `SchemaConstraintTests` 의 테이블 수도 맞춘다.

## 도메인 규칙

- 기준 데이터(사용자·조직·그룹·역할·리소스·권한·범위·정책·직무 분리·SSO 클라이언트)는 **지우지 않고 끈다**. 연결(역할의 권한, 예외)은 기간을 끝내 회수한다. 코드 값(사번, 역할·리소스 키 등)은 바꾸지 않는다.
- 끈 것이 실제로 효력을 잃는지(PDP·로그인·토큰 발급) 테스트로 확인한다.
- IAM 관리 콘솔 자신의 클라이언트(`iam-admin`)와 리소스·권한은 끌 수 없게 막는다 (끄면 관리자도 되돌릴 수 없다).
- 관리 API 에는 `@RequiresPermission`(또는 본인 일이면 `@SelfService`)을 붙인다. 새 리소스는 `ApiResources.CATALOG` 에 추가하면 기동 시 관리자 역할이 권한을 받는다.
- **관리 콘솔 권한이 있는 역할**(`iam-admin` 리소스 권한)은 직접 할당만 한다. 조직·그룹 규칙으로 주지 않고(`ConsoleRoleGrantGuard`), 비상 접근은 승인 후 시작만, 위임은 MFA 로그인으로만, 접근 재검토는 조직장이 아니라 관리자가 한다. 조직 단위 관리자는 이런 역할을 가졌거나 곧 받을 사람을 바꿀 수 없다. **역할을 주는 새 경로를 만들면 이 규칙을 같이 건다** — 보안 점검에서 같은 검사가 형제 경로에만 빠진 것이 여러 번 나왔다 (규칙: [docs/security.md](docs/security.md) "관리자 보호").

## 함정 (실제로 걸린 것)

- **SAS 토큰 claim 은 String·Boolean·`ArrayList` 만.** SAS 는 인가 기록을 JSON 으로 저장했다가 다시 읽는데 Kotlin 리스트·`Long` 은 거부해 refresh 가 깨진다. ID 는 문자열로 넣는다.
- **로그인 후 돌아갈 곳**은 인가 요청(`/oauth2/authorize`)과 패스키 관리 화면(`GET /account/passkeys`)만 저장한다. 로그인 체인의 request cache 는 그 화면 하나만 저장하고, MFA 대기 중에는 저장하지 않는다. favicon·CSS·다른 탭 요청이 덮어써 엉뚱한 곳으로 가던 버그가 있었다.
- **SAS 는 로그인 인증의 `FactorGrantedAuthority` 발급 시각으로 ID 토큰 `auth_time` 을 정한다.** 인증 토큰을 새로 만들 때(패스키 로그인) 이 권한을 버리고 `SimpleGrantedAuthority` 로 바꾸면 토큰 발급이 실패한다.
- 로그인 화면 정적 자원은 `/iam-login/**` 아래에 둔다 (보안 체인·MFA 필터가 이 경로를 통과시킨다).
- **보안 필터에서 경로를 볼 때는 `requestURI` 문자열을 비교하지 말고 `PathPatternRequestMatcher` 를 쓴다.** Spring 의 엔드포인트는 디코딩한 경로로 맞추므로 문자열 비교면 `/oauth2/%61uthorize`, `/webauthn/%72egister` 같은 표기로 검사를 건너뛴다 (두 번 걸렸다).
- **"센 뒤 막는" 제한(시도 횟수 등)은 대상 행을 먼저 잠그고 `READ COMMITTED` 로 센다.** MySQL 기본(REPEATABLE READ)은 트랜잭션에서 처음 읽은 시점의 값을 계속 보므로, 잠가도 동시 요청이 모두 같은 횟수를 읽고 통과한다 (`PasswordResetService.verify`).
- 브라우저 세션은 DB 에 직렬화해 저장한다(Spring Session JDBC). 세션에 넣는 값은 `Serializable` 이어야 한다.
- 테스트 결과는 실행 전 `build/test-results` 를 지우고 본다. 컴파일이 실패하면 예전 결과 파일이 남아 통과한 것처럼 보인다.
- 테스트에서 DB 시각을 `Timestamp.from(Instant)` 로 직접 쓰면 시간대(DB 세션은 KST)만큼 밀릴 수 있다. 시각을 바꿀 때는 `expire_at = login_at` 처럼 DB 안의 값으로 맞춘다.
- 기본 위험 정책의 "평소와 다른 시간"(07~22시 밖) 신호는 실행 시각에 따라 붙는다. 위험 점수를 확인하는 테스트는 그 정책을 끄고 본다 (밤에만 실패하던 테스트가 있었다).

## 검증

- 백엔드: `cd backend && ./gradlew build` (Docker 필요, Testcontainers). 패키지를 옮겼으면 `clean build`.
- 콘솔: `cd admin && pnpm exec tsc --noEmit && pnpm lint && pnpm build`. **개발 서버가 떠 있으면 먼저 멈추고 빌드한 뒤 `.next` 를 지우고 다시 띄운다** (같은 폴더를 써서 새로고침 반복·예전 화면이 생긴다). `.next` 를 지운 직후 tsc 는 `PageProps` 를 못 찾으므로 `pnpm exec next typegen` 을 먼저 돌린다.
- `docs/integration/*.md` 는 관리 콘솔이 빌드 때 읽어 개발자 가이드로 보여 준다. 고쳤으면 콘솔 빌드로 확인한다.
- 시스템 구조도는 `docs/architecture.html` 이 원본이고 `architecture.png`·`architecture-dark.png` 는 거기서 뽑는다(캔버스 1000×660, 2배). 원본을 고치면 두 PNG 도 다시 뽑는다.
- 화면을 바꿨으면 브라우저로 확인한다. 로그인이 필요한 화면은 직접 볼 수 없으니, 로그인 없이 열리는 화면(`/login-failed`, IAM `/login`)으로 공통 부분을 확인하고 나머지는 확인 못 했다고 말한다.
- 관리자 비밀번호 등 `.env` 의 값은 읽거나 출력하지 않는다.

## 저장소

- GitHub `dublesy/didrakon-iam`. 커밋 작성자는 이 저장소 로컬 설정의 dublesy 다.
- 개인 환경에만 해당하는 절차(푸시할 계정 전환 등)는 git 에 올리지 않는 `CLAUDE.local.md` 에 둔다.
- 커밋·푸시는 사용자가 요청할 때만 한다.
