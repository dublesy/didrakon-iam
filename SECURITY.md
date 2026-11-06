# Security Policy / 보안 정책

## Reporting a vulnerability / 취약점 신고

**Please do not open a public issue for security vulnerabilities.**
보안 취약점은 공개 이슈로 올리지 마세요.

Report privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). Only the maintainers can see the report.

GitHub 저장소의 **Security** 탭에서 **Report a vulnerability** 를 눌러 비공개로 알려 주세요. 신고 내용은 관리자만 볼 수 있습니다.

Please include / 다음을 함께 적어 주세요:

- the affected version or commit / 영향을 받는 버전 또는 커밋
- the endpoint, screen or code path / 엔드포인트·화면·코드 위치
- steps to reproduce and the observed result / 재현 방법과 실제 결과
- the impact you expect (whose data or authority is affected) / 예상 영향 (누구의 데이터·권한에 영향이 있는지)

Test only against your own local or test installation. Do not test against systems you do not own.
본인이 직접 띄운 로컬·테스트 환경에서만 확인해 주세요. 다른 사람이 운영하는 시스템을 대상으로 시험하지 마세요.

## What happens next / 처리 절차

- We acknowledge the report within 7 days. / 7일 안에 접수 여부를 알려 드립니다.
- We confirm the issue, prepare a fix and agree on a disclosure date with you. / 문제를 확인하고 수정한 뒤, 공개 시점을 신고자와 정합니다.
- With your permission, we credit you in the release notes. / 원하시면 릴리스 노트에 신고자를 밝힙니다.

## Supported versions / 지원 버전

Security fixes go to the latest commit on `main`. There are no separately maintained release branches yet.
보안 수정은 `main` 의 최신 커밋에 반영합니다. 아직 따로 유지하는 릴리스 브랜치는 없습니다.

## Scope / 대상

In scope: the IAM server (`backend/`), the admin console (`admin/`) and the integration examples (`examples/`).
Out of scope: vulnerabilities in third-party dependencies that are already publicly known (please report those upstream), and issues that require an already fully trusted global administrator (`IAM_ADMIN`) unless they cross a documented boundary.

대상: IAM 서버(`backend/`), 관리 콘솔(`admin/`), 연동 예제(`examples/`).
대상 아님: 이미 공개된 외부 라이브러리 취약점(해당 프로젝트에 신고해 주세요), 그리고 문서에 적힌 경계를 넘지 않는 한 전체 관리자(`IAM_ADMIN`)만 할 수 있는 동작.
