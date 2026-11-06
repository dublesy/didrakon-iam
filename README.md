# DIDRAKON IAM

계정·로그인·권한을 한곳에서 관리하는 IAM 플랫폼입니다. SSO(OIDC), 권한 판정(RBAC + ABAC + ReBAC), 권한 거버넌스, 위험 평가, 감사를 함께 제공합니다.

사번, 인사 시스템 연동, 조직 단위 관리자, 정기 접근 권한 점검처럼 국내 기업 조직에 필요한 기능을 기본으로 갖췄습니다.

> 이름은 그리스어 *di*(둘) + *drakōn*(용)에서 왔습니다. 인증과 인가, 두 마리 용이 문을 지킵니다.

[English](README.en.md) · [문서](#문서) · [빠른 시작](#빠른-시작) · [보안 신고](SECURITY.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="docs/architecture-dark.png">
  <img alt="DIDRAKON IAM 시스템 구조" src="docs/architecture.png">
</picture>

## 주요 기능

- **로그인(SSO)**: OIDC 로그인·인가 서버, 계정 잠금, 인증 앱(TOTP), 패스키, API 키, 인증 앱으로 셀프 비밀번호 재설정
- **권한 판정**: 역할(조직·리소스 범위), 규칙 버전이 있는 ABAC 정책과 예외, 조직·그룹 역할 규칙. 다른 시스템은 `POST /api/v1/authz/check` 로 묻는다
- **권한 거버넌스**: 임시 권한(JIT) 요청과 승인, 직무 분리, 위임, 비상 접근, 접근 재검토(증적 CSV)
- **사람과 조직**: 조직도, 겸직, 그룹, 내부 임직원과 외부(B2B) 사용자, 인사 시스템 연동(입사·이동·휴직·퇴사)
- **위험 평가**: 새 기기, 해외 IP, 평소와 다른 시간, 연속 실패, 대량 접근 신호로 로그인을 막거나 추가 인증 요구
- **감사**: 기준 데이터·역할·정책 변경을 전후 값과 함께 기록, 서명한 웹훅으로 다른 시스템에 알림
- **관리 콘솔**: Next.js BFF (토큰이 브라우저로 가지 않음), 조직 단위 관리자 화면, 개발자 연동 가이드

## 빠른 시작

필요한 것: Docker, Node.js + pnpm. JDK 25 는 Gradle 이 자동으로 내려받습니다.

**1. 설정 파일 만들기**

```bash
cp .env.example .env
```

`.env` 에서 아래 값을 채웁니다.

| 값 | 설명 |
|---|---|
| `IAM_SECRET_KEY` | MFA 비밀값 암호화 키 (필수). `openssl rand -base64 32` 로 만든다 |
| `IAM_BOOTSTRAP_ADMIN_LOGIN` | 첫 관리자 로그인 ID (처음 기동할 때만) |
| `IAM_BOOTSTRAP_ADMIN_PASSWORD` | 첫 관리자 비밀번호 (처음 기동할 때만) |

그 밖의 값(`IAM_ISSUER`, `IAM_CONSOLE_URL`, JWT 서명 키 등)은 `.env.example` 의 설명을 봅니다.

**2. DB 와 IAM 서버 띄우기**

```bash
docker compose up -d
```

```bash
cd backend && set -a && source ../.env && set +a && ./gradlew :iam-app:bootRun
```

로컬 프로필은 처음 기동할 때 화면 확인용 예시 데이터(가상 회사 "누리케어")를 만듭니다. 끄려면 `application-local.yml` 의 `iam.demo-data.enabled` 를 `false` 로 합니다.

**3. 관리 콘솔 띄우기**

`admin/.env.example` 을 `admin/.env.local` 로 복사하고 `SESSION_SECRET` 을 채운 뒤 실행합니다.

```bash
cd admin && pnpm install && pnpm dev
```

**4. 로그인**

http://localhost:3000 에서 관리자로 로그인 → `2단계 인증` 메뉴에서 인증 앱 등록 → 다시 로그인하면 관리 기능을 쓸 수 있습니다.

> 운영(`prod` 프로필)은 JWT 서명 키(`IAM_JWT_PRIVATE_KEY`·`IAM_JWT_PUBLIC_KEY`)가 없으면 기동하지 않습니다. 패스키는 `localhost` 밖에서는 https 가 필요합니다.

## 문서

| 문서 | 내용 |
|---|---|
| [구조](docs/architecture.md) | 모듈 구성과 의존 방향, 모듈 간 이벤트 |
| [보안](docs/security.md) | 토큰·세션·회수, 로그인 보호, 패스키, 관리자 보호 |
| [API](docs/api.md) | 관리·권한 판정·본인 API 목록 |
| [관리 콘솔](docs/admin-console.md) | 동작 방식, 메뉴, 코드 위치 |
| [데이터 모델과 규칙](docs/erd-v2.md) | 테이블, 도메인 규칙, HR 연동 규칙 |
| [다른 시스템 연동](docs/integration/README.md) | 스택별 빠른 시작, 데이터 이관, 검증한 예제 앱 |
| [화면 디자인 규칙](admin/DESIGN.md) | 콘솔의 색·글꼴·문구 규칙 |

## 빌드와 테스트

테스트는 Testcontainers 로 MySQL 을 띄우므로 Docker 가 실행 중이어야 합니다.

```bash
cd backend && ./gradlew build
```

```bash
cd admin && pnpm build && pnpm lint
```

콘솔의 `pnpm build` 와 `pnpm dev` 는 같은 `.next` 폴더를 씁니다. 개발 서버를 띄운 채 빌드했다면 `.next` 를 지우고 개발 서버를 다시 띄웁니다.

## 기술 스택

| 영역 | 사용 기술 |
|---|---|
| 서버 | Kotlin 2.4, Spring Boot 4.1, Spring Authorization Server, Spring Security WebAuthn |
| 데이터 | MySQL 8.4, Flyway, JPA + QueryDSL 7 |
| 관리 콘솔 | Next.js 16, React 19, pnpm |
| 실행 환경 | JDK 25 |

## 보안 신고와 라이선스

보안 취약점은 공개 이슈로 올리지 말고 [SECURITY.md](SECURITY.md) 의 방법으로 알려 주세요.

라이선스: [Apache License 2.0](LICENSE)
