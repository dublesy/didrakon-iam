# IAM ERD v2

## 1. 확정된 설계 원칙

| 항목 | 결정 |
|---|---|
| 스택 | Kotlin, Spring Boot 4.1, QueryDSL(OpenFeign 포크, KSP), MySQL 8.4 LTS, Next.js |
| PK | `BIGINT AUTO_INCREMENT` (Spring Authorization Server 표준 테이블만 예외) |
| 대량 적재 | AUTHENTICATION_EVENT, AUTHORIZATION_LOG, AUDIT_EVENT는 JDBC batch, 물리 FK 없음 |
| 계층 조회 | `WITH RECURSIVE` native query |
| 예약어 | `GROUP` → `USER_GROUP` |
| JSON | MySQL `JSON` 타입 |
| 시간 | `DATETIME(6)`, KST(`Asia/Seoul`). 코드에서는 `Instant`만 사용 |
| Subject 상속 | JOINED, 애그리거트 간 ID 참조 |
| 권한 판정 | `ROLE_ASSIGNMENT` 단일 경로. 그룹·조직·JIT·위임·Break-glass 모두 행 생성 |
| 충돌 규칙 | deny-overrides, 예외는 `POLICY_EXCEPTION`으로만 |
| 삭제 | 마스터 데이터는 비활성화, 연결 데이터는 hard delete + 이력 |
| 테넌시 | 단일 테넌트. 법인은 조직 트리(`COMPANY`)와 scope로 분리 |
| 인증 | Spring Security 7 Authorization Server |

## 2. ERD

```mermaid
erDiagram

    %% =========================================================
    %% 1. SUBJECT / IDENTITY
    %% =========================================================

    SUBJECT {
        bigint subject_id PK
        varchar subject_type "USER, SERVICE, AI_AGENT, APPLICATION"
        varchar subject_name
        varchar status "ACTIVE, LOCKED, DISABLED, RETIRED"
        varchar description
        datetime created_at
        datetime updated_at
    }

    USER {
        bigint subject_id PK,FK
        varchar user_kind "EMPLOYEE, EXTERNAL (V17)"
        varchar emp_no UK "그룹 전체 고유. EXTERNAL 은 NULL (V17)"
        varchar name
        varchar email "EXTERNAL 은 필수, EXTERNAL 끼리 고유"
        varchar phone
        varchar employment_status "EMPLOYED, LEAVE, RETIRED"
        date hire_date "그룹 최초 입사일"
        date retire_date
        datetime last_login_at
    }

    SERVICE_ACCOUNT {
        bigint subject_id PK,FK
        varchar service_name
        bigint owner_subject_id FK
        varchar environment "DEV, STG, PROD"
        datetime last_used_at
    }

    AI_AGENT {
        bigint subject_id PK,FK
        varchar agent_name
        varchar agent_type
        bigint owner_subject_id FK
        varchar model_name
        varchar risk_level "LOW, MEDIUM, HIGH, CRITICAL"
        boolean is_autonomous
    }

    APPLICATION {
        bigint subject_id PK,FK
        varchar application_name
        varchar application_type "WEB, MOBILE, API, BATCH"
        bigint owner_subject_id FK
        varchar environment
    }

    IDENTITY_PROVIDER {
        bigint provider_id PK
        varchar provider_code UK
        varchar provider_name
        varchar provider_type "LOCAL, OIDC, SAML, LDAP, AD"
        varchar issuer
        varchar metadata_url
        boolean is_active
        datetime created_at
    }

    IDENTITY {
        bigint identity_id PK
        bigint subject_id FK
        bigint provider_id FK
        varchar external_id "UK(provider_id, external_id)"
        varchar login_id
        varchar email
        boolean is_primary
        boolean is_verified
        datetime last_login_at
    }

    LOCAL_CREDENTIAL {
        bigint identity_id PK,FK
        varchar password_hash
        datetime password_changed_at
        datetime password_expire_at
        int failed_attempt_count
        datetime locked_until
    }


    %% =========================================================
    %% 2. ORGANIZATION / MEMBERSHIP
    %% =========================================================

    ORGANIZATION {
        bigint org_id PK
        bigint parent_org_id FK
        bigint company_org_id FK "소속 법인 (비정규화)"
        varchar org_code UK
        varchar org_name
        varchar org_type "GROUP, COMPANY, DIVISION, DEPARTMENT, TEAM, CENTER"
        int org_level
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    SUBJECT_ORGANIZATION {
        bigint membership_id PK
        bigint subject_id FK
        bigint org_id FK
        varchar membership_type "PRIMARY, SECONDARY, TEMPORARY"
        varchar job_title "소속별 직위"
        varchar job_grade "소속별 직급"
        boolean is_manager
        datetime valid_from
        datetime valid_until
    }

    ORGANIZATION_ROLE {
        bigint org_role_id PK
        bigint org_id FK
        bigint role_id FK
        bigint scope_id FK
        boolean apply_to_descendants "하위 조직 구성원에게도 부여"
        boolean is_active
        datetime valid_from
        datetime valid_until
    }


    %% =========================================================
    %% 3. GROUP
    %% =========================================================

    USER_GROUP {
        bigint group_id PK
        varchar group_code UK
        varchar group_name
        varchar group_type "STATIC, DYNAMIC"
        json rule_expression
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    GROUP_MEMBER {
        bigint group_id PK,FK
        bigint subject_id PK,FK
        varchar source_type "MANUAL, RULE, SYNC"
        datetime valid_from
        datetime valid_until
    }

    GROUP_ROLE {
        bigint group_role_id PK
        bigint group_id FK
        bigint role_id FK
        bigint scope_id FK
        datetime valid_from
        datetime valid_until
    }


    %% =========================================================
    %% 4. SSO CLIENT / SESSION (Spring Authorization Server)
    %% =========================================================

    SSO_CLIENT {
        bigint client_id PK
        varchar registered_client_id FK "OAUTH2_REGISTERED_CLIENT.id"
        varchar client_code UK
        varchar client_name
        varchar client_type "WEB, API, MOBILE, BATCH"
        varchar protocol "OIDC, SAML"
        boolean require_mfa
        varchar backchannel_logout_uri "V11"
        boolean supabase_role_claim "토큰에 role=authenticated (V20)"
        varchar home_url "앱 런처 시작 주소 (V21)"
        boolean is_active
        datetime created_at
    }

    OAUTH2_REGISTERED_CLIENT {
        varchar id PK "SAS 표준 스키마 (발췌)"
        varchar client_id
        varchar client_secret "PasswordEncoder로 인코딩"
        varchar redirect_uris
        varchar post_logout_redirect_uris
        varchar scopes
        varchar client_settings
        varchar token_settings
    }

    OAUTH2_AUTHORIZATION {
        varchar id PK "SAS 표준 스키마 (발췌)"
        varchar registered_client_id
        varchar principal_name
        varchar authorization_grant_type
        varchar authorization_code_value "SHA-256 hex(64), INDEX"
        varchar access_token_value "SHA-256 hex(64), INDEX"
        varchar refresh_token_value "SHA-256 hex(64), INDEX"
        varchar oidc_id_token_value "SHA-256 hex(64), INDEX. 외 컬럼 생략"
    }

    OAUTH2_AUTHORIZATION_CONSENT {
        varchar registered_client_id PK
        varchar principal_name PK
        varchar authorities
    }

    LOGIN_SESSION {
        bigint session_id PK
        varchar session_key_hash UK "외부 노출 세션 키의 hash"
        bigint subject_id FK
        bigint identity_id FK
        varchar device_id
        varchar ip_address
        varchar user_agent
        varchar authentication_level "PASSWORD, MFA, CERTIFICATE"
        datetime login_at
        datetime expire_at
        datetime last_activity_at
        varchar status "ACTIVE, EXPIRED, REVOKED"
    }


    %% =========================================================
    %% 5. MFA / AUTHENTICATION EVENT
    %% =========================================================

    MFA_METHOD {
        bigint mfa_method_id PK
        bigint subject_id FK
        varchar method_type "TOTP, SMS, EMAIL, FIDO2, PASSKEY"
        varchar secret_reference
        boolean is_primary
        boolean is_verified
        datetime registered_at
    }

    AUTHENTICATION_EVENT {
        bigint authentication_event_id PK "대량 적재, 물리 FK 없음"
        bigint subject_id
        bigint identity_id
        varchar event_type "LOGIN, LOGOUT, MFA, PASSWORD_CHANGE, FAILED_LOGIN"
        varchar result "SUCCESS, FAILURE, CHALLENGE"
        varchar ip_address
        varchar device_id
        varchar user_agent
        varchar failure_reason
        datetime created_at
    }


    %% =========================================================
    %% 6. RESOURCE / RELATION
    %% =========================================================

    RESOURCE {
        bigint resource_id PK
        bigint client_id FK
        bigint parent_resource_id FK
        varchar resource_key "UK(client_id, resource_key)"
        varchar resource_name
        varchar resource_type "SYSTEM, MENU, API, DATA, BUTTON, DOCUMENT"
        varchar resource_path
        varchar sensitivity "PUBLIC, INTERNAL, CONFIDENTIAL, SECRET"
        boolean is_active
        datetime created_at
    }

    RELATION_TYPE {
        bigint relation_type_id PK
        varchar relation_code UK "OWNS, MANAGES, APPROVES, BELONGS_TO, MEMBER_OF, ASSIGNED_TO"
        varchar relation_name
        varchar description
    }

    RESOURCE_RELATION {
        bigint resource_relation_id PK
        bigint source_resource_id FK
        bigint relation_type_id FK
        bigint target_resource_id FK
        datetime valid_from
        datetime valid_until
    }

    SUBJECT_RELATION {
        bigint subject_relation_id PK
        bigint subject_id FK
        bigint relation_type_id FK
        bigint target_subject_id FK "target 둘 중 하나만 (CHECK)"
        bigint target_resource_id FK
        datetime valid_from
        datetime valid_until
    }


    %% =========================================================
    %% 7. SCOPE
    %% =========================================================

    SCOPE {
        bigint scope_id PK
        varchar scope_code UK
        varchar scope_name
        varchar scope_type "GLOBAL, ORGANIZATION, RESOURCE, PROJECT, DATA"
        bigint org_id FK
        bigint resource_id FK
        bigint parent_scope_id FK
        json scope_expression
        boolean include_descendants "하위 조직·리소스 포함"
        boolean is_active
    }

    DATA_SCOPE {
        bigint data_scope_id PK
        bigint scope_id FK
        varchar data_type "EMPLOYEE, PAYROLL, CUSTOMER, CONTRACT"
        json condition_expression
        json masking_policy
        json row_filter_expression
    }


    %% =========================================================
    %% 8. ROLE / PERMISSION
    %% =========================================================

    ROLE {
        bigint role_id PK
        varchar role_code UK
        varchar role_name
        varchar role_type "SYSTEM, BUSINESS, CUSTOM, PRIVILEGED"
        int priority "표시 순서·설명용, 판정 결과에는 영향 없음"
        boolean is_sensitive
        boolean is_privileged
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    PERMISSION {
        bigint permission_id PK
        varchar permission_code UK
        varchar permission_name
        bigint resource_id FK
        varchar action "READ, CREATE, UPDATE, DELETE, EXECUTE, APPROVE, EXPORT"
        varchar effect "ALLOW, DENY"
        boolean is_sensitive
        boolean is_active
    }

    ROLE_PERMISSION {
        bigint role_permission_id PK
        bigint role_id FK "UK(role_id, permission_id, scope_id)"
        bigint permission_id FK
        bigint scope_id FK "NOT NULL, 미지정 시 GLOBAL scope"
        datetime valid_from
        datetime valid_until
    }


    %% =========================================================
    %% 9. ROLE ASSIGNMENT (권한 판정 단일 경로)
    %% =========================================================

    ROLE_ASSIGNMENT {
        bigint assignment_id PK
        bigint subject_id FK
        bigint role_id FK
        bigint scope_id FK "NOT NULL"
        varchar source_type "DIRECT, GROUP, ORGANIZATION, JIT, DELEGATION, BREAK_GLASS, SYSTEM"
        bigint source_id "출처 행 ID (논리 참조)"
        datetime valid_from
        datetime valid_until
        varchar status "ACTIVE, EXPIRED, REVOKED"
        boolean review_required "전적 등으로 재검토 필요"
        bigint assigned_by FK
        varchar reason
        datetime revoked_at
        bigint revoked_by FK
        datetime created_at
    }


    %% =========================================================
    %% 10. ABAC POLICY
    %% =========================================================

    POLICY {
        bigint policy_id PK
        varchar policy_code UK
        varchar policy_name
        varchar policy_type "AUTHORIZATION, SECURITY, DATA, RISK"
        varchar effect "ALLOW, DENY, CHALLENGE, REQUIRE_APPROVAL"
        int priority "표시 순서·설명용, 판정 결과에는 영향 없음"
        boolean is_active
        datetime created_at
        datetime updated_at
    }

    POLICY_VERSION {
        bigint policy_version_id PK
        bigint policy_id FK
        int version "UK(policy_id, version)"
        varchar status "DRAFT, ACTIVE, RETIRED"
        varchar change_reason
        bigint created_by FK
        datetime created_at
    }

    POLICY_RULE {
        bigint rule_id PK
        bigint policy_version_id FK
        int rule_group "같은 그룹은 AND, 그룹 간은 OR"
        varchar attribute_source "SUBJECT, RESOURCE, CONTEXT, RELATION, SESSION"
        varchar attribute_name
        varchar operator "EQ, NE, IN, NOT_IN, GT, LT, BETWEEN, MATCH, EXISTS"
        json attribute_value
        int rule_order
    }

    POLICY_TARGET {
        bigint policy_target_id PK
        bigint policy_id FK
        bigint permission_id FK "셋 중 하나만 (CHECK)"
        bigint resource_id FK
        bigint role_id FK
    }

    POLICY_EXCEPTION {
        bigint exception_id PK
        bigint policy_id FK
        bigint subject_id FK
        bigint resource_id FK
        varchar reason
        datetime valid_from
        datetime valid_until
    }


    %% =========================================================
    %% 11. ACCESS REQUEST / APPROVAL (JIT, Break-glass 공용)
    %% =========================================================

    ACCESS_REQUEST {
        bigint request_id PK
        varchar request_type "JIT, BREAK_GLASS"
        bigint subject_id FK
        bigint role_id FK
        bigint scope_id FK
        varchar reason
        varchar risk_level "LOW, MEDIUM, HIGH, CRITICAL"
        datetime requested_start
        datetime requested_end
        varchar status "PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED"
        datetime created_at
    }

    APPROVAL_POLICY {
        bigint approval_policy_id PK
        varchar policy_name
        varchar resource_sensitivity
        varchar role_type
        int required_approval_count
        boolean require_security_team
        boolean require_owner
        boolean is_active
    }

    APPROVAL {
        bigint approval_id PK
        bigint request_id FK
        bigint approver_id FK
        bigint approval_policy_id FK
        int approval_step
        varchar status "PENDING, APPROVED, REJECTED, SKIPPED"
        varchar comment
        datetime decided_at
    }


    %% =========================================================
    %% 12. RISK
    %% =========================================================

    RISK_POLICY {
        bigint risk_policy_id PK
        varchar policy_name
        varchar risk_type "LOGIN, DATA_ACCESS, PRIVILEGE, JIT"
        json condition_expression
        int risk_score
        varchar action "ALLOW, DENY, CHALLENGE, APPROVAL"
        boolean is_active
    }

    RISK_SIGNAL {
        bigint risk_signal_id PK
        bigint subject_id FK
        varchar signal_type "NEW_DEVICE, FOREIGN_IP, UNUSUAL_TIME, MASS_ACCESS"
        int risk_score
        json details
        datetime detected_at
    }

    RISK_ASSESSMENT {
        bigint assessment_id PK
        bigint subject_id FK
        bigint request_id FK
        int risk_score
        varchar risk_level "LOW, MEDIUM, HIGH, CRITICAL"
        varchar decision "ALLOW, DENY, CHALLENGE, APPROVAL"
        datetime assessed_at
    }


    %% =========================================================
    %% 13. SEGREGATION OF DUTIES
    %% =========================================================

    ROLE_CONFLICT {
        bigint conflict_id PK
        bigint role_id_a FK "role_id_a < role_id_b, UK(a, b)"
        bigint role_id_b FK
        varchar conflict_type "MUTUAL_EXCLUSION"
        varchar severity "LOW, MEDIUM, HIGH, CRITICAL"
        varchar description
        boolean is_active
    }

    ROLE_CONFLICT_EXCEPTION {
        bigint exception_id PK
        bigint conflict_id FK
        bigint subject_id FK
        bigint approved_by FK
        varchar reason
        datetime valid_from
        datetime valid_until
        boolean is_active
    }


    %% =========================================================
    %% 14. DELEGATION
    %% =========================================================

    DELEGATION {
        bigint delegation_id PK
        bigint delegator_id FK
        bigint delegate_id FK
        bigint role_id FK
        bigint scope_id FK
        datetime start_time
        datetime end_time
        varchar reason
        varchar status "PENDING, ACTIVE, EXPIRED, REVOKED"
        datetime created_at
    }


    %% =========================================================
    %% 15. BREAK GLASS
    %% =========================================================

    BREAK_GLASS_POLICY {
        bigint break_glass_policy_id PK
        varchar policy_name
        bigint role_id FK
        bigint scope_id FK
        boolean require_reason
        boolean require_approval
        boolean require_mfa
        int max_duration_minutes
        boolean is_active
    }

    BREAK_GLASS_SESSION {
        bigint break_glass_session_id PK
        bigint break_glass_policy_id FK
        bigint subject_id FK
        bigint request_id FK "승인 필요 시"
        bigint assignment_id FK "생성된 ROLE_ASSIGNMENT"
        varchar reason
        datetime start_time
        datetime end_time
        varchar status "ACTIVE, EXPIRED, REVOKED"
        bigint revoked_by FK
    }


    %% =========================================================
    %% 16. AUTHORIZATION LOG
    %% =========================================================

    AUTHORIZATION_LOG {
        bigint authorization_log_id PK "대량 적재, 물리 FK 없음"
        varchar trace_id
        bigint subject_id
        bigint resource_id
        varchar action
        bigint scope_id
        bigint session_id
        json context
        varchar decision "ALLOW, DENY, CHALLENGE, REQUIRE_APPROVAL"
        varchar decision_reason
        bigint matched_policy_id
        bigint matched_role_id
        bigint matched_permission_id
        bigint matched_assignment_id
        bigint matched_relation_id
        int risk_score
        json explanation "판정 근거 목록"
        int evaluation_time_ms
        datetime decided_at
    }


    %% =========================================================
    %% 17. API KEY / SERVICE CREDENTIAL
    %% =========================================================

    API_KEY {
        bigint api_key_id PK
        bigint subject_id FK
        bigint client_id FK
        varchar key_hash UK
        varchar key_name
        json scope_expression
        datetime issued_at
        datetime expire_at
        datetime last_used_at
        boolean revoked
    }

    SERVICE_CREDENTIAL {
        bigint credential_id PK
        bigint subject_id FK
        varchar credential_type "CLIENT_SECRET, CERTIFICATE, PRIVATE_KEY"
        varchar secret_reference
        datetime issued_at
        datetime expire_at
        boolean revoked
    }


    %% =========================================================
    %% 18. AUDIT
    %% =========================================================

    AUDIT_EVENT {
        bigint event_id PK "대량 적재, 물리 FK 없음"
        bigint actor_subject_id
        bigint target_subject_id
        varchar event_type "LOGIN, LOGOUT, ROLE_CHANGE, PERMISSION_CHANGE, MEMBERSHIP_CHANGE, JIT, POLICY_CHANGE, DATA_ACCESS"
        varchar resource_type
        varchar resource_id
        varchar action
        json before_value
        json after_value
        varchar reason
        varchar trace_id
        varchar ip_address
        varchar device_id
        varchar user_agent
        datetime created_at
    }

    POLICY_CHANGE_HISTORY {
        bigint history_id PK
        bigint policy_id FK
        int old_version
        int new_version
        bigint changed_by FK
        varchar change_reason
        json old_value
        json new_value
        datetime changed_at
    }

    ROLE_CHANGE_HISTORY {
        bigint history_id PK
        bigint role_id FK
        bigint subject_id FK
        varchar change_type "ASSIGN, REVOKE, MODIFY, REVIEW, EXPIRE"
        bigint assignment_id FK
        bigint changed_by FK
        varchar reason
        datetime changed_at
    }


    %% =========================================================
    %% RELATIONSHIPS  (-- 물리 FK, .. 논리 참조)
    %% =========================================================

    %% SUBJECT
    SUBJECT ||--o| USER : "is_user"
    SUBJECT ||--o| SERVICE_ACCOUNT : "is_service"
    SUBJECT ||--o| AI_AGENT : "is_ai_agent"
    SUBJECT ||--o| APPLICATION : "is_application"

    SUBJECT ||--o{ IDENTITY : "has_identity"
    IDENTITY_PROVIDER ||--o{ IDENTITY : "provides"
    IDENTITY ||--o| LOCAL_CREDENTIAL : "local_password"

    %% ORGANIZATION
    ORGANIZATION ||--o{ ORGANIZATION : "parent_child"
    ORGANIZATION ||--o{ ORGANIZATION : "company_of"

    SUBJECT ||--o{ SUBJECT_ORGANIZATION : "belongs_to"
    ORGANIZATION ||--o{ SUBJECT_ORGANIZATION : "has_member"

    ORGANIZATION ||--o{ ORGANIZATION_ROLE : "has_role"
    ROLE ||--o{ ORGANIZATION_ROLE : "assigned_to_org"
    SCOPE ||--o{ ORGANIZATION_ROLE : "limits"

    %% GROUP
    SUBJECT ||--o{ GROUP_MEMBER : "member_of"
    USER_GROUP ||--o{ GROUP_MEMBER : "contains"

    USER_GROUP ||--o{ GROUP_ROLE : "has_role"
    ROLE ||--o{ GROUP_ROLE : "assigned_to_group"
    SCOPE ||--o{ GROUP_ROLE : "limits"

    %% SSO
    OAUTH2_REGISTERED_CLIENT ||--o| SSO_CLIENT : "extends"
    OAUTH2_REGISTERED_CLIENT ||--o{ OAUTH2_AUTHORIZATION : "issues"
    OAUTH2_REGISTERED_CLIENT ||--o{ OAUTH2_AUTHORIZATION_CONSENT : "consents"

    SUBJECT ||--o{ LOGIN_SESSION : "has_session"
    IDENTITY ||--o{ LOGIN_SESSION : "authenticates"

    SUBJECT ||--o{ MFA_METHOD : "has_mfa"
    SUBJECT ||..o{ AUTHENTICATION_EVENT : "generates"

    %% RESOURCE
    SSO_CLIENT ||--o{ RESOURCE : "owns"
    RESOURCE ||--o{ RESOURCE : "parent_child"

    RELATION_TYPE ||--o{ RESOURCE_RELATION : "defines"
    RESOURCE ||--o{ RESOURCE_RELATION : "source"
    RESOURCE ||--o{ RESOURCE_RELATION : "target"

    RELATION_TYPE ||--o{ SUBJECT_RELATION : "defines"
    SUBJECT ||--o{ SUBJECT_RELATION : "source"
    SUBJECT ||--o{ SUBJECT_RELATION : "target_subject"
    RESOURCE ||--o{ SUBJECT_RELATION : "target_resource"

    %% SCOPE
    ORGANIZATION ||--o{ SCOPE : "defines"
    RESOURCE ||--o{ SCOPE : "defines"
    SCOPE ||--o{ SCOPE : "parent_child"
    SCOPE ||--o{ DATA_SCOPE : "contains"

    %% ROLE / PERMISSION
    ROLE ||--o{ ROLE_PERMISSION : "contains"
    PERMISSION ||--o{ ROLE_PERMISSION : "assigned_to"
    SCOPE ||--o{ ROLE_PERMISSION : "limits"
    RESOURCE ||--o{ PERMISSION : "defines"

    %% ROLE ASSIGNMENT
    SUBJECT ||--o{ ROLE_ASSIGNMENT : "receives"
    ROLE ||--o{ ROLE_ASSIGNMENT : "assigned"
    SCOPE ||--o{ ROLE_ASSIGNMENT : "limits"

    %% POLICY
    POLICY ||--o{ POLICY_VERSION : "versions"
    POLICY_VERSION ||--o{ POLICY_RULE : "contains"

    POLICY ||--o{ POLICY_TARGET : "targets"
    PERMISSION ||--o{ POLICY_TARGET : "target_permission"
    RESOURCE ||--o{ POLICY_TARGET : "target_resource"
    ROLE ||--o{ POLICY_TARGET : "target_role"

    POLICY ||--o{ POLICY_EXCEPTION : "has_exception"
    SUBJECT ||--o{ POLICY_EXCEPTION : "excluded_subject"
    RESOURCE ||--o{ POLICY_EXCEPTION : "excluded_resource"

    %% ACCESS REQUEST
    SUBJECT ||--o{ ACCESS_REQUEST : "requests"
    ROLE ||--o{ ACCESS_REQUEST : "requested_role"
    SCOPE ||--o{ ACCESS_REQUEST : "requested_scope"

    ACCESS_REQUEST ||--o{ APPROVAL : "requires"
    SUBJECT ||--o{ APPROVAL : "approves"
    APPROVAL_POLICY ||--o{ APPROVAL : "controls"

    %% RISK
    SUBJECT ||--o{ RISK_SIGNAL : "generates"
    SUBJECT ||--o{ RISK_ASSESSMENT : "evaluated"
    ACCESS_REQUEST ||--o{ RISK_ASSESSMENT : "risk_checked"

    %% SoD
    ROLE ||--o{ ROLE_CONFLICT : "conflict_a"
    ROLE ||--o{ ROLE_CONFLICT : "conflict_b"
    ROLE_CONFLICT ||--o{ ROLE_CONFLICT_EXCEPTION : "exception"
    SUBJECT ||--o{ ROLE_CONFLICT_EXCEPTION : "approved_subject"

    %% DELEGATION
    SUBJECT ||--o{ DELEGATION : "delegates"
    SUBJECT ||--o{ DELEGATION : "receives"
    ROLE ||--o{ DELEGATION : "delegated_role"
    SCOPE ||--o{ DELEGATION : "delegated_scope"

    %% BREAK GLASS
    ROLE ||--o{ BREAK_GLASS_POLICY : "emergency_role"
    SCOPE ||--o{ BREAK_GLASS_POLICY : "emergency_scope"
    BREAK_GLASS_POLICY ||--o{ BREAK_GLASS_SESSION : "creates"
    SUBJECT ||--o{ BREAK_GLASS_SESSION : "uses"
    ACCESS_REQUEST ||--o| BREAK_GLASS_SESSION : "approved_by"
    ROLE_ASSIGNMENT ||--o| BREAK_GLASS_SESSION : "grants"

    %% AUTHORIZATION LOG (논리 참조)
    SUBJECT ||..o{ AUTHORIZATION_LOG : "requests"
    RESOURCE ||..o{ AUTHORIZATION_LOG : "target"

    %% CREDENTIALS
    SUBJECT ||--o{ API_KEY : "owns"
    SSO_CLIENT ||--o{ API_KEY : "issued_for"
    SUBJECT ||--o{ SERVICE_CREDENTIAL : "owns"

    %% AUDIT
    SUBJECT ||..o{ AUDIT_EVENT : "actor"
    POLICY ||--o{ POLICY_CHANGE_HISTORY : "changed"
    ROLE ||--o{ ROLE_CHANGE_HISTORY : "changed_role"
    SUBJECT ||--o{ ROLE_CHANGE_HISTORY : "changed_subject"
    ROLE_ASSIGNMENT ||--o{ ROLE_CHANGE_HISTORY : "changed_assignment"
```

## 3. 원본 대비 변경 사항

### 삭제·통합된 테이블

| 원본 | 변경 | 이유 |
|---|---|---|
| `TEMPORARY_GRANT` | 삭제 → `ROLE_ASSIGNMENT(source_type=JIT, source_id=request_id)` | 권한 판정 단일 경로 |
| `PERMISSION_LINEAGE` | 삭제 → `ROLE_ASSIGNMENT` + `ROLE_PERMISSION` 조인으로 계산 | `ROLE_ASSIGNMENT`가 출처(source_type, source_id)를 이미 가지고 있어 별도 저장이 중복 |
| `ACCESS_TOKEN`, `REFRESH_TOKEN` | 삭제 → SAS `OAUTH2_AUTHORIZATION` | Spring Authorization Server가 토큰 상태를 관리 |
| `RESOURCE_RELATION_TYPE` | `RELATION_TYPE`으로 통합 | 동일 구조 중복 |
| `AUTHORIZATION_REQUEST`, `AUTHORIZATION_DECISION`, `AUTHORIZATION_EXPLANATION` | `AUTHORIZATION_LOG` 1개로 통합, 설명은 JSON 컬럼 | 1:1:N 구조를 3개 테이블에 매 요청마다 적재하면 insert가 3배. 조회는 대부분 한 건 단위 |

### 추가된 테이블

| 테이블 | 이유 |
|---|---|
| `LOCAL_CREDENTIAL` | 자체 IdP(SAS)로 비밀번호 로그인을 하려면 비밀번호 hash 저장소가 필요한데 원본에 없음 |
| `OAUTH2_REGISTERED_CLIENT`, `OAUTH2_AUTHORIZATION`, `OAUTH2_AUTHORIZATION_CONSENT` | SAS 표준 스키마. 라이브러리 소유라 PK 규칙(BIGINT) 예외 |

### 이름 변경

| 원본 | 변경 | 이유 |
|---|---|---|
| `GROUP` | `USER_GROUP` | MySQL 예약어 |
| `SESSION` | `LOGIN_SESSION` | SAS·Spring Session의 세션 개념과 구분 |
| `BREAK_GLASS_SESSION.policy_id` | `break_glass_policy_id` | `POLICY` 테이블과 혼동 방지 |
| `request_id` (AUDIT, AUTHORIZATION) | `trace_id` | `ACCESS_REQUEST.request_id`와 이름 충돌 |
| `last_login` | `last_login_at` | 시간 컬럼 명명 통일 |

### 컬럼·구조 변경

| 테이블 | 변경 | 이유 |
|---|---|---|
| 전체 | PK·FK를 `BIGINT`로, 표현식·값 컬럼을 `JSON`으로 | 확정 사항 |
| `USER` | `job_title`, `job_grade` 제거, `emp_no` UK | 겸직 시 직위가 소속마다 다름. 사번은 그룹 전체 고유 |
| `USER` | `user_kind`(EMPLOYEE·EXTERNAL) 추가, `emp_no` NULL 허용 (V17) | B2B 고객사 사용자 같은 외부 사용자는 사번이 없고 이메일로 식별한다. 인사 연동 대상이 아니다 |
| `SUBJECT_ORGANIZATION` | 대리 키 `membership_id`, `job_title`, `job_grade` 추가 | 같은 조직에 재소속(전적 후 복귀)되면 `(subject_id, org_id)` 복합 PK가 충돌 |
| `ORGANIZATION` | `company_org_id` 추가, `org_type`에 `GROUP`, `CENTER` 추가 | 법인 판별을 재귀 없이 처리 |
| `ORGANIZATION_ROLE` | `inheritance_type` → `apply_to_descendants`, `scope_id` 추가 | 의미를 명확히 하고, 생성될 ROLE_ASSIGNMENT의 scope 지정 |
| `GROUP_ROLE` | 대리 키, `scope_id` 추가 | 같은 그룹에 같은 역할을 scope만 다르게 부여 가능 |
| `ROLE_PERMISSION` | 대리 키, `UK(role_id, permission_id, scope_id)`, `scope_id NOT NULL` | 원본 PK로는 scope만 다른 동일 권한 부여 불가 |
| `ROLE_ASSIGNMENT` | `source_type`에 `BREAK_GLASS` 추가, `review_required`, `revoked_at`, `revoked_by` 추가 | Break-glass도 단일 경로로 통합, 전적 시 재검토 표시 |
| `ROLE_CHANGE_HISTORY` | `change_type`에 `EXPIRE` 추가 | 유효 기간 종료를 회수(REVOKE)와 구분 |
| `SSO_CLIENT` | `client_secret`, `redirect_uris`, `logout_uris`, `token_policy` 제거 → SAS 테이블로 | 비밀값이 평문 컬럼에 있던 문제 해결 (SAS는 PasswordEncoder로 인코딩) |
| `LOGIN_SESSION` | `client_id` 제거, `session_key_hash` 추가 | IdP 로그인 세션은 여러 클라이언트에 걸침. 외부 노출 키는 순번 ID가 아닌 랜덤 값의 hash |
| `SCOPE` | `include_descendants` 추가 | "법인A scope = 하위 센터 포함" 표현 |
| `POLICY` | `current_version` 제거 | `POLICY_VERSION.status=ACTIVE`와 중복 |
| `POLICY_VERSION` | `is_active` → `status`, `policy_expression` 제거 | 초안·활성·폐기 구분. 규칙의 원본은 `POLICY_RULE` 하나로 |
| `POLICY_RULE` | `logical_operator` → `rule_group` | 원본은 AND/OR 우선순위를 표현할 수 없음. `(A AND B) OR C` → 그룹1: A, B / 그룹2: C |
| `POLICY_TARGET` | 대리 키, 대상 FK 셋 중 하나만 (CHECK) | 원본 PK에 `permission_id`가 있어 리소스·역할만 대상으로 지정 불가 |
| `ACCESS_REQUEST` | `request_type` 추가, `permission_id`, `resource_id` 제거 | JIT와 Break-glass 승인 흐름 공용. 역할 단위로만 요청 (아래 결정 사항 1) |
| `DELEGATION` | `permission_id` 제거 | 역할 단위로만 위임 (아래 결정 사항 1) |
| `BREAK_GLASS_POLICY` | `reason_required` → `require_reason` (boolean) | 원본이 string 타입 |
| `BREAK_GLASS_SESSION` | `approval_id` → `request_id`, `assignment_id` 추가 | 원본 `APPROVAL`은 `ACCESS_REQUEST`에 묶여 있어 Break-glass 승인과 연결이 끊겨 있었음 |
| `SUBJECT_RELATION` | target 둘 중 하나만 (CHECK) | 둘 다 null이거나 둘 다 있는 행 방지 |
| `OAUTH2_AUTHORIZATION` | 토큰·코드 값 컬럼 `BLOB` → `VARCHAR(64)` SHA-256 hex + 인덱스 | SAS 기본 구현은 평문 저장이라 DB 유출 시 토큰을 그대로 쓸 수 있고, 인덱스 없는 BLOB 비교라 조회가 전체 스캔 (아래 결정 사항 3) |
| SAS 표준 테이블 | `timestamp` → `DATETIME(6)` | 프로젝트 시간 규칙 통일, `TIMESTAMP`의 2038년 한계 회피 |
| `USER` | `hire_date`, `retire_date`를 `DATE`로 | 입사·퇴사는 날짜 개념. 코드에서는 `LocalDate` |
| `SERVICE_ACCOUNT` | `description` 제거 | `SUBJECT.description`과 중복. JOINED 상속에서 상위 컬럼을 쓴다 |
| `POLICY_EXCEPTION` | 대상(subject, 리소스) 중 하나 이상 필수 (CHECK) | 대상 없는 예외는 정책 전체를 무력화함 |
| `AUTHENTICATION_EVENT`, `AUTHORIZATION_LOG`, `AUDIT_EVENT` | PK에 시간 컬럼 포함 (`(id, created_at)` 등) | MySQL 파티션 테이블은 파티션 키가 모든 UNIQUE 키에 포함되어야 함. 나중에 월 단위 파티셔닝을 PK 변경 없이 적용 |

### 스키마 작성 규칙

ERD에 길이·NULL 여부가 없는 컬럼은 아래 규칙으로 정했다. 마이그레이션: `backend/iam-app/src/main/resources/db/migration` (도메인별 `V1__identity` ~ `V6__audit`)

| 대상 | 규칙 |
|---|---|
| 코드(`*_code`) | `VARCHAR(100)`, UK |
| 이름(`*_name`) | `VARCHAR(200)` |
| 설명·사유(`description`, `reason`, `comment`) | `VARCHAR(1000)` |
| enum 성격 컬럼 | `VARCHAR(30)` + 주석에 허용 값. MySQL `ENUM` 타입은 쓰지 않음 |
| hash | `VARCHAR(64)` (SHA-256 hex) |
| IP / user agent | `VARCHAR(45)` / `VARCHAR(500)` |
| 비밀값 | 값 대신 보관소 참조(`secret_reference`)만 저장 |
| boolean | `BOOLEAN NOT NULL` + 기본값 |
| 유효 기간 | `valid_from NOT NULL`, `valid_until` NULL = 기한 없음 |
| 이름 규칙 | `fk_<테이블>_<의미>`, `uk_`, `idx_`, `ck_` 접두어 |

## 4. ERD에 표현되지 않는 제약

| 대상 | 제약 | 구현 |
|---|---|---|
| `USER` | EMPLOYEE 는 `emp_no`, EXTERNAL 은 `email` 필수. EXTERNAL `email` 은 EXTERNAL 끼리 고유 (임직원 이메일과는 겹쳐도 됨) | CHECK `ck_user_kind_identifier` + generated column `external_email = IF(user_kind='EXTERNAL', email, NULL)` + UNIQUE (V17). 서비스 레이어(`UserService`)에서도 검증. EXTERNAL 은 만들 때 소속 조직(고객사)이 필요 |
| `SUBJECT_ORGANIZATION` | 활성 PRIMARY 소속은 subject당 1개 | generated column `active_primary_subject_id = IF(membership_type='PRIMARY' AND valid_until IS NULL, subject_id, NULL)` + UNIQUE. 서비스 레이어(`MembershipService`)에서도 검증 |
| `ROLE_PERMISSION`, `ROLE_ASSIGNMENT` | `scope_id NOT NULL` | MySQL UNIQUE는 NULL을 서로 다른 값으로 취급해 중복을 막지 못함. scope 미지정은 GLOBAL scope 행을 참조 |
| `POLICY_TARGET`, `SUBJECT_RELATION` | 대상 FK 중 하나만 NOT NULL | MySQL 8.0.16+ CHECK 제약 |
| `POLICY_EXCEPTION` | subject, 리소스 중 하나 이상 NOT NULL | CHECK 제약 |
| `ROLE_CONFLICT` | `role_id_a < role_id_b` | CHECK + UK로 (A,B)와 (B,A) 중복 방지 |
| `POLICY_VERSION` | 정책당 ACTIVE 1개 | 서비스 레이어 검증 |
| `ORGANIZATION.company_org_id` | 조직 이동 시 하위 조직 전체 갱신 | `OrganizationService.move`가 `WITH RECURSIVE`로 하위 조직을 찾아 레벨·소속 법인 재계산. 자기 하위로 이동은 거부 |
| `AUTHENTICATION_EVENT`, `AUTHORIZATION_LOG`, `AUDIT_EVENT` | 물리 FK 없음 | MySQL 파티션 테이블은 FK를 지원하지 않음. 나중에 월 단위 파티셔닝 가능하도록 |
| `OAUTH2_AUTHORIZATION` | 토큰 값은 hash로만 저장 | 커스텀 `OAuth2AuthorizationService`가 저장·조회 시 SHA-256 적용. 저장된 값을 클라이언트에 다시 줄 수 없으므로 모든 클라이언트 `reuseRefreshTokens=false`(refresh token 회전) |

### 전적(Mover) 처리 규칙

| 권한 출처 | 처리 |
|---|---|
| `source_type=ORGANIZATION` | 자동 재계산 (이전 법인 회수, 새 법인 부여) |
| 직접 할당 + scope가 이전 법인 | 자동 회수 + 감사 기록 |
| 직접 할당 + scope가 그룹 전체 | 유지, `review_required = true` |
| 겸직(SECONDARY) 법인 권한 | 영향 없음 |

구현(`MoverHandler`) 세부:
- 전적은 PRIMARY 소속의 **법인**(`company_org_id`)이 바뀐 경우만. 같은 법인 안의 이동(전보)은 조직 역할 재계산만 한다.
- scope의 법인은 `scope.org_id`가 속한 법인이다. `org_id`가 없거나(GLOBAL·RESOURCE 등) 법인 위 조직(GROUP)이면 "그룹 전체"로 본다.
- 이전 법인에 겸직·임시 소속이 남아 있으면 그 법인 범위 직접 할당은 회수하지 않는다.
- "감사 기록"은 모든 할당 변경 시 발행하는 `RoleAssignmentChangedEvent`를 audit 모듈이 받아 `ROLE_CHANGE_HISTORY`와 `AUDIT_EVENT`로 남긴다.

### 조직·그룹 역할 동기화

`ORGANIZATION_ROLE`, `GROUP_ROLE`은 규칙이고, 판정은 규칙이 만든 `ROLE_ASSIGNMENT` 행만 읽는다 (단일 경로).

| 항목 | 규칙 |
|---|---|
| 방식 | subject 단위로 "규칙상 있어야 할 할당"과 "실제 활성 할당"을 비교해 부족분은 부여, 남는 것은 회수 (`OrganizationRoleSync`, `GroupRoleSync`). 몇 번을 실행해도 결과가 같다 |
| 조직 규칙 적용 대상 | 소속 조직의 규칙은 전부, 상위 조직의 규칙은 `apply_to_descendants = true`인 것만. PRIMARY·SECONDARY·TEMPORARY 소속 모두 포함 |
| 할당 출처 | `source_type = ORGANIZATION / GROUP`, `source_id = org_role_id / group_role_id`. 같은 규칙에 여러 소속으로 해당해도 할당은 1개 |
| 트리거 | identity가 같은 트랜잭션에서 발행하는 이벤트: 소속 생성·종료, PRIMARY 이동, 조직 이동, 그룹 구성원 추가·제거. 규칙 생성·비활성화·삭제 시에도 해당 구성원을 다시 맞춘다 |
| 회수 | 규칙·소속이 사라진 할당은 `REVOKED`로 바꾼다 (삭제하지 않음). 직접 회수 API는 `DIRECT` 할당만 받는다 |

### 권한 판정(PDP) 규칙

`PolicyDecisionPoint.decide(subject, resource, action, orgId?, context, session)`

1. **RBAC**: 유효한 할당(`ACTIVE` + 유효 기간 안 + 역할 활성) × 유효한 `ROLE_PERMISSION` 중에서 **할당 scope와 권한 scope가 모두 요청을 덮는** 것만 쓴다.
   - 하나도 없으면 `DENY` (기본 거부).
   - `effect = DENY` 권한이 하나라도 있으면 `DENY` (deny-overrides).
2. **ABAC**: RBAC이 허용했을 때만 평가한다. 정책은 권한을 새로 주지 않는다.
   - 적용 정책: 활성 정책 중 대상(`POLICY_TARGET`)이 허용에 쓰인 권한·역할이거나, 요청 리소스 또는 그 **상위 리소스**인 것. 대상이 없는 정책은 적용되지 않는다.
   - `ACTIVE` 버전의 규칙만 평가한다. 규칙이 없으면 조건은 항상 참이다.
   - 효과: `DENY`·`CHALLENGE`·`REQUIRE_APPROVAL`은 조건이 맞을 때 적용. `ALLOW`는 **조건부 허용**이라 조건이 맞지 않으면 `DENY`.
   - `POLICY_EXCEPTION`에 해당하면(지정한 subject·리소스가 모두 일치) 그 정책을 건너뛴다.
   - 결과가 여럿이면 가장 강한 것: `DENY > REQUIRE_APPROVAL > CHALLENGE > ALLOW`.
3. 모든 판정은 `AUTHORIZATION_LOG`에 근거(`explanation`)와 함께 남긴다 (JDBC 직접 insert).

scope 매칭:

| scope_type | 요청을 덮는 조건 |
|---|---|
| GLOBAL | 항상 |
| ORGANIZATION | 요청 `orgId`가 scope 조직과 같거나, `include_descendants`이고 그 하위 조직. `orgId`가 없으면 매칭 안 됨 |
| RESOURCE | 요청 리소스가 scope 리소스와 같거나, `include_descendants`이고 그 하위 리소스 |
| PROJECT, DATA | RBAC에서 해석하지 않음 (매칭 안 됨) |

ABAC 규칙(`POLICY_RULE`)에서 쓸 수 있는 속성 (`AttributeCollector`):

| attribute_source | attribute_name |
|---|---|
| SUBJECT | `subjectType`, `userKind`(사용자일 때 `EMPLOYEE`·`EXTERNAL`), `status`, `employmentStatus`, `orgIds`, `companyOrgIds`, `primaryOrgId`, `primaryCompanyOrgId`, `isManager`, `roleCodes` |
| RESOURCE | `resourceId`, `resourceKey`, `resourceType`, `sensitivity`, `clientId` |
| CONTEXT | 호출 측이 넘긴 `context` + `orgId` |
| SESSION | 호출 측이 넘긴 `session` |
| RELATION | subject가 요청 리소스와 맺은 관계 코드 (예: `OWNS`). `EXISTS`로 검사 |

IAM 자신의 관리 API 판정: `@RequiresPermission(orgOf = …)` 로 경로의 대상(사용자 → 활성 PRIMARY 소속 조직, 없으면 다른 활성 소속 하나 / 조직 → 그 조직 / 소속 → 그 조직 / 세션 → 주인의 조직)을 `orgId` 로 넘긴다. 대상 조직을 찾지 못하거나 조직과 무관한 API 면 `orgId` 없이 판정하므로 GLOBAL(·RESOURCE) 범위 권한만 통과한다. 자세한 것은 아래 "조직 단위 관리 규칙".

연산자 의미: 속성이 없으면 규칙은 거짓(`NE`, `NOT_IN` 포함). 속성이 목록이면 `EQ`·`MATCH`는 "하나라도", `IN`은 "겹침", `NOT_IN`은 "겹치지 않음". `GT`·`LT`·`BETWEEN`은 숫자끼리 또는 문자열끼리(예: `"09:00"`) 비교하고 `BETWEEN`은 양 끝을 포함한다. 규칙 값의 모양은 버전 생성 시 검증한다.

### 조직 단위 관리 규칙

전체 관리자(`IAM_ADMIN`)가 사람에게 `IAM_ORG_ADMIN` 역할을 **ORGANIZATION 범위**(`include_descendants = true` 권장)로 할당하면, 그 사람은 그 조직(과 하위)의 사람·소속·조직·로그인 세션만 관리한다. 구현은 `iam-app` 의 `AdminAuthorizer`·`PermissionInterceptor`, 범위 계산은 `iam-authz` 의 `OrgReachService`.

| 항목 | 규칙 |
|---|---|
| 역할 | `IAM_ORG_ADMIN`(SYSTEM, 민감): 사용자 READ·CREATE·UPDATE, 소속 READ·CREATE·UPDATE·DELETE, 조직 READ·UPDATE, 세션 READ·DELETE. 역할·할당·정책·리소스·범위·클라이언트·위험·webhook·재검토·HR 연동 권한은 없다 (스스로 권한을 넓히지 못하게). 관리 API MFA 정책 대상이다 |
| 대상 판정 | 사용자·조직·소속·세션 API 는 경로의 대상 조직을 `orgId` 로 PDP 에 넘긴다 (위 "권한 판정(PDP) 규칙"). 범위 밖이면 403. 소속이 하나도 없는 사람은 전체 범위 권한만 다룬다 |
| 본문의 대상 | 사용자 생성은 `primaryOrgId`(같은 트랜잭션에서 PRIMARY 소속 생성)가 범위 안이어야 하고, 비우면 전체 범위 권한만. 주 소속 이동은 지금 조직과 옮길 조직이 모두, 소속 추가는 대상 사람과 조직이 모두, 조직 이동은 옮길 조직과 새 상위 조직이 모두 범위 안이어야 한다 |
| 다른 관리자 보호 | 조직 범위로만 권한이 있는 관리자는 IAM 관리 API 권한을 가진 사람(전체 관리자·다른 조직 단위 관리자 등)을 바꿀 수 없다(조회는 된다). 같은 조직에 있는 전체 관리자의 비밀번호 초기화·사용 중지 같은 권한 탈취·무력화를 막는다. 본인은 예외 |
| 목록 | 사용자 목록은 활성 PRIMARY 소속 조직이 범위 안인 사람만, 조직 목록은 범위 안 조직만(상위 조직은 빠짐), 이름 조회(`/subjects/names`)는 범위 안 조직에 활성 소속이 있는 사람만. 조직 구성원 목록은 범위 안 조직만 열린다(그 조직의 겸직자는 보인다) |
| 범위 계산 | 유효한 할당 × 유효한 역할 권한(허용만)에서 할당 scope ∩ 권한 scope 를 조직 집합으로 펼친다. GLOBAL·RESOURCE → 전체, ORGANIZATION → 그 조직(하위 포함 시 하위 전체), PROJECT·DATA → 없음. DENY 권한·ABAC 정책은 목록 거르기에 반영하지 않고, 호출 자체는 PDP 가 판정한다 |
| 전체 전용 API | 역할·리소스·권한·범위·할당·조직/그룹 역할 규칙·정책·직무 분리·승인·재검토·위험·webhook·HR 연동·클라이언트·API 키·감사·그룹·조직 생성은 `orgId` 없이 판정하므로 조직 범위 할당으로는 403 이다. **조직 단위 관리자는 역할을 줄 수 없다** |
| 관리 API MFA 정책 | `IAM_ADMIN_API_MFA` 는 콘솔·API 로 끄거나 대상·규칙을 바꿀 수 없다(409). 켜고 끄기는 `iam.bootstrap.require-mfa-for-admin` 설정으로 한다 |
| 규칙으로 주는 역할 | 관리 콘솔 권한(`iam-admin` 리소스)이 있는 역할은 조직·그룹 역할 규칙에 넣을 수 없고, 규칙에 쓰는 역할에는 콘솔 권한을 더할 수 없다(409). 직접 할당만 한다. 소속을 바꿀 수 있는 조직 단위 관리자가 자기나 다른 사람을 그 조직에 넣어 관리 역할을 얻지 못하게 한다 |
| 콘솔 | `GET /api/v1/me/admin-scope` → `{global, orgIds, resources: [{resource, actions}]}`. 메뉴와 화면 영역(역할·위험·감사 등)은 이 값으로 보이고 숨긴다. 실제 허용은 API 마다 PDP 가 판정한다 |

### 감사 기록 규칙

| 항목 | 규칙 |
|---|---|
| 시점 | 업무 변경과 **같은 트랜잭션**에서 쓴다. 감사 기록이 실패하면 업무 변경도 롤백되므로 기록 없는 권한 변경이 생기지 않는다 |
| 방식 | 각 모듈이 발행한 도메인 이벤트를 audit 모듈이 구독한다. audit는 맨 끝 소비자라 다른 모듈은 audit에 의존하지 않는다 |
| 행위자 | 이벤트에 명시된 행위자(`changedBy` 등)가 우선, 없으면 `RequestContextHolder`의 행위자. 규칙·전적으로 시스템이 바꾼 할당은 그 변경을 일으킨 요청의 행위자로 남는다. 둘 다 없으면 NULL(시스템) |
| 출처 | `trace_id`, `ip_address`, `user_agent`, `device_id`는 `RequestContextHolder`에서 채운다 |
| `AUDIT_EVENT` 쓰기 | JDBC 직접 insert (대량 적재 테이블) |

| 이벤트 | 기록 |
|---|---|
| 역할 할당 생성·회수·재검토 표시 | `ROLE_CHANGE_HISTORY` + `AUDIT_EVENT(ROLE_CHANGE)`, action = `ASSIGN`/`REVOKE`/`REVIEW`, after = 역할·scope·출처 |
| 조직 소속 생성·종료 | `AUDIT_EVENT(MEMBERSHIP_CHANGE)`, action = `JOIN`/`LEAVE`, 조직·소속 유형 |
| PRIMARY 소속 이동 | `AUDIT_EVENT(MEMBERSHIP_CHANGE)`, action = `TRANSFER`, before/after = 이전·새 조직 |
| 그룹 구성원 추가·제거 | `AUDIT_EVENT(MEMBERSHIP_CHANGE)`, action = `ADD`/`REMOVE` |
| 정책 버전 활성화 | `POLICY_CHANGE_HISTORY`(이전·새 버전의 효과와 규칙 전체 스냅샷) + `AUDIT_EVENT(POLICY_CHANGE)`, action = `ACTIVATE` |
| 로그인·로그아웃 (authn) | `AUDIT_EVENT(LOGIN/LOGOUT)` (`AUTHENTICATION_EVENT` 와 별도로) |
| 접근 요청·비상 접근 (governance) | `AUDIT_EVENT(JIT)`, action = 요청 상태 |
| 기준 데이터 수정·켜기·끄기·퇴사 | `AUDIT_EVENT`, before/after = 바뀐 값 (유형은 "관리 변경 규칙" 참고) |
| 위험 정책 추가·수정·켜기·끄기 | `AUDIT_EVENT(POLICY_CHANGE)`, resource_type = `RISK_POLICY` |
| 접근 재검토 시작·마감·항목 결정 (governance) | `AUDIT_EVENT(ROLE_CHANGE)`, resource_type = `ACCESS_REVIEW_CAMPAIGN`(action `REVIEW_CAMPAIGN_CREATE`/`ESCALATE`/`CLOSE`) · `ACCESS_REVIEW_ITEM`(action `REVIEW_KEEP`/`REVIEW_REVOKE`, after = 캠페인·할당·결정자·자동 여부, reason = 의견). 회수·유지 확인은 역할 할당 변경으로도 남는다 |

조회(`AuditQueryService`): 감사 이벤트는 기간 필수(최대 1,000건, 최신순)이고 subject(행위자 또는 대상)·유형으로 거른다. 역할 변경 이력은 subject별, 정책 변경 이력은 정책별로 조회한다.

미기록 항목: 조직 이동(`AUDIT_EVENT.event_type`에 해당 유형 없음), 권한 판정(`AUTHORIZATION_LOG`가 따로 남김).

미구현 표시: 스키마·enum 에만 있고 동작하는 코드가 없는 값 — `IDENTITY_PROVIDER.provider_type` 의 SAML·LDAP·AD, `MFA_METHOD.method_type` 의 SMS·EMAIL·FIDO2 (패스키는 구현했지만 `MFA_METHOD` 가 아니라 V18 의 `user_entities`·`user_credentials` 에 두므로 `PASSKEY` 값은 쓰지 않는다), `SSO_CLIENT.protocol` 의 SAML, `approval_policy.resource_sensitivity`, PROJECT·DATA scope 판정.

### 인증 규칙 (authn)

| 항목 | 규칙 |
|---|---|
| 로그인 | LOCAL IdP(V7 초기 데이터) 계정의 로그인 ID + 비밀번호. 인증 후 principal 이름과 토큰 `sub` 는 **subject ID** |
| 비밀번호 변경 | 본인은 현재 비밀번호를 맞혀야 바꾼다(틀리면 실패 횟수에 셈). 관리자가 초기화하면 `LOCAL_CREDENTIAL.must_change_password`(V10)가 켜져 다음 로그인에서 본인이 바꿔야 한다. 만료됐거나 초기화된 계정은 비밀번호를 맞힌 뒤에만 변경 화면(`/login/password`, 10분 유효)으로 가고(이때 세션 ID 를 바꾼다), 바꾼 뒤 새 비밀번호로 다시 로그인한다. 지금 비밀번호와 같은 값은 거부. 어떤 경로로든(본인·셀프 재설정·만료·관리자 초기화) 비밀번호가 바뀌면 그 사람의 로그인 세션과 발급한 토큰을 모두 끝낸다(`PasswordChangedEvent`). API 키는 따로 관리하므로 두고, 필요하면 폐기한다 |
| 잠금 | 비밀번호 오류와 MFA 코드 오류를 합쳐 5회 연속이면 30분 잠금(`LOCAL_CREDENTIAL.locked_until`). MFA 단계에서 잠기면 진행 중인 로그인도 끝낸다. 실패 기록은 로그인 요청이 실패해도 남도록 별도 트랜잭션으로 커밋. 성공하면 횟수 초기화. 관리자는 `POST /api/v1/users/{id}/unlock` 으로 비밀번호를 바꾸지 않고 풀 수 있다(감사 `USER`·`UNLOCK`) |
| 셀프 재설정 | 메일·문자 수단이 없으므로 확인을 마친 TOTP 로 본인을 확인한다. `/login/forgot` 에 로그인 ID + 인증 앱 코드 → 맞으면 비밀번호 변경 화면(`/login/password`, 10분 유효)으로 가고, 새 비밀번호를 정하면 잠금·실패 횟수도 풀린다(잠긴 계정의 본인 해제). 사용자 상태가 ACTIVE 가 아니면 거부. 없는 계정·TOTP 없음·틀린 코드·제한 초과는 모두 같은 문구. 로그인 잠금과 별도로 계정마다 1시간에 실패 5회면 코드가 맞아도 거부한다: `AUTHENTICATION_EVENT`(`PASSWORD_CHANGE`, 사유 `PASSWORD_RESET_OK`·`PASSWORD_RESET_FAILED`·`PASSWORD_RESET_LIMITED`) 중 `FAILED` 행을 센다. 감사는 `LOGIN`·`PASSWORD_RESET_SUCCESS`/`FAILURE` |
| 비밀번호 | 최소 10자, 로그인 ID 포함 금지, 90일 만료(설정값). 저장은 `{bcrypt}` 등 DelegatingPasswordEncoder 형식 |
| 로그인 세션 | 로그인마다 `LOGIN_SESSION` 1건. 브라우저에는 무작위 키, DB 에는 hash. 관리자가 종료하면 그 브라우저의 다음 요청에서 다시 로그인 |
| MFA | TOTP(RFC 6238). 확인을 마친 TOTP 가 있으면 비밀번호 다음에 반드시 거친다. `SSO_CLIENT.require_mfa` 클라이언트는 TOTP 나 패스키 없이 로그인할 수 없다(authorize 경로는 SAS 와 같이 디코딩한 경로로 맞춘다. `/oauth2/%61uthorize` 같은 표기로 건너뛸 수 없다). 수단을 더하거나 지우는 본인 API 는 API 키로는 못 쓰고, 이미 수단이 있으면 MFA·패스키로 로그인한 토큰이어야 한다. 성공하면 세션 수준 `MFA`, 토큰 `amr = [pwd, otp]` |
| 패스키 로그인 | WebAuthn(Spring Security). 사용자 확인(생체·PIN) 필수라 그 자체로 MFA: 세션 수준 `MFA`, 토큰 `amr = [hwk, user]`, TOTP 를 다시 묻지 않는다. 관리 API MFA 정책(`IAM_ADMIN_API_MFA`)은 `amr NOT_IN ["otp","hwk"]` 일 때 CHALLENGE — 그 전 규칙(`["otp"]`)이 그대로면 기동할 때 새 버전으로 바꾼다. 위험 평가 DENY 는 막고 CHALLENGE 는 충족한 것으로 기록(`LOGIN/CHALLENGE`, 사유 끝 "패스키로 충족"). 성공 인증 이벤트 사유 `PASSKEY`. 실패는 `FAILED_LOGIN`(사유 `PASSKEY: …`)으로만 남기고 비밀번호 실패 횟수는 건드리지 않는다. 사용자 상태가 ACTIVE 가 아니거나 비밀번호·코드 실패로 일시 잠겨(`locked_until`) 있으면 거부(`/login?unavailable`) — 잠금은 그 계정에 공격이 있다는 신호라 어떤 방법으로도 들어오지 못하게 한다. 잠금은 만료·셀프 재설정·관리자 해제로 풀린다 |
| 패스키 등록 | IAM 화면 `/account/passkeys`(Spring `/webauthn/register`). 2단계 인증(TOTP 또는 패스키)을 거친 로그인에서만 등록·삭제한다. WebAuthn 사용자 이름(`user_entities.name`)은 subject ID, 인증기에 보이는 이름은 로그인 ID. 저장은 V18 `user_entities`·`user_credentials`(Spring 표준 스키마, ERD 외 테이블). 등록·삭제는 감사 `LOGIN`·`PASSKEY_ADD`/`PASSKEY_REMOVE` |
| TOTP 재사용 | 성공한 코드의 시간 구간을 `MFA_METHOD.last_used_step`(V8)에 남기고, 같거나 이전 구간의 코드는 거부한다. 검증은 행 잠금(`SELECT … FOR UPDATE`)으로 동시 요청을 막는다 |
| 위험 평가 | 비밀번호 확인 직후 LOGIN 위험을 평가한다(아래 위험 규칙). 결과가 DENY 면 로그인을 되돌리고 `/login?risk` 로 보낸다. 실패 횟수는 초기화하지 않는다 |
| 서명 키 | JWT 서명 RSA 키는 `IAM_JWT_PRIVATE_KEY`·`IAM_JWT_PUBLIC_KEY`. 없으면 기동마다 새 키라 재기동 시 기존 토큰이 무효가 된다. `prod` 는 키 없이 기동하지 않는다 (`iam.authn.require-persistent-jwt-key`) |
| 비밀값 | `MFA_METHOD.secret_reference` 에는 참조만. 실제 값은 `SecretStore` 가 보관하며, 지금 구현은 앱 키(`IAM_SECRET_KEY`)로 AES-GCM 암호화해 `secret_value` 테이블(V7, ERD 외 테이블)에 둔다 |
| 토큰 | SAS 토큰·code 는 SHA-256 hash 로만 저장(결정 사항 3). refresh token 은 매번 회전, 이전 값은 거부 |
| 토큰 회수 | 인가 기록은 저장될 때 그 브라우저의 로그인 세션과 연결된다(`login_session_authorization`, V10). 로그아웃·관리자 세션 종료 → 그 세션에서 나온 인가 삭제(refresh 불가). 사용 안 함·잠김·퇴사 → 모든 세션 종료, 모든 인가 삭제, API 키 폐기. 접근 토큰(JWT, 10분)은 만료까지 남지만 PDP 가 비활성 주체를 거부한다 |
| 토큰 claim | 사용자 토큰(접근·ID)에 `name`, `user_kind`(EMPLOYEE·EXTERNAL), `emp_no`(임직원만), `primary_org_id`, `company_org_id`(문자열), `roles`(유효한 역할 코드). client credentials 토큰에는 넣지 않는다. 토큰 수명 동안은 바뀐 값이 반영되지 않으므로 거친 판단(메뉴 노출)에만 쓰고 세밀한 판단은 `/api/v1/authz/check` |
| 퇴사 | `POST /api/v1/users/{id}/retire`: 소속 종료·그룹 제외(→ 조직·그룹 할당 회수), 남은 할당 전부 회수, `status = RETIRED`, `employment_status = RETIRED`, 퇴사일 기록. 되돌릴 수 없다. 퇴사일이 오늘 이후면 `USER.retire_date` 에 예약만 하고(상태는 그대로), 만료 스케줄러가 그날 처리한다. 예약은 `DELETE` 로 취소 |
| IAM 홈 | 로그인 서버의 `/`(내 계정). 내 앱은 `SSO_CLIENT.home_url`(V21)을 둔 켜진 WEB·MOBILE 클라이언트 바로가기다 (접근 권한은 각 시스템이 판단). 로그인된 기기는 본인의 유효한 `LOGIN_SESSION`, 최근 로그인 기록은 본인의 `AUTHENTICATION_EVENT` 10건. `다른 기기에서 모두 로그아웃`은 지금 브라우저의 로그인 세션만 남기고 나머지를 끝낸다 (토큰 회수·back-channel 로그아웃 포함, 감사 LOGOUT). 콘솔 링크는 `iam.authn.console-url`(`IAM_CONSOLE_URL`) |
| Supabase 호환 | `SSO_CLIENT.supabase_role_claim`(V20)을 켠 클라이언트에 발급하는 접근·ID 토큰에 `role: "authenticated"` 를 넣는다. Supabase Third-Party Auth(Custom OIDC)가 이 값이 있어야 로그인한 사용자로 보기 때문이다. 끈 클라이언트에는 넣지 않는다 |
| 계정 연결 조회 | `POST /api/v1/users/lookup` 은 연동 시스템이 기존 계정을 잇는 일회성 작업용으로 사번·이메일 목록(합쳐 1000건)을 받아 맞는 사용자를 돌려준다. 사번은 하나, 이메일은 대소문자를 무시하고 여러 명(임직원·외부 사용자)일 수 있다. 개인정보가 URL 에 남지 않도록 POST 본문으로 받고, 사용자 조회 전체 범위 권한만 쓸 수 있다 |
| back-channel 로그아웃 | `SSO_CLIENT.backchannel_logout_uri`(V11)를 등록한 클라이언트는, 그 클라이언트에 발급한 인가가 회수될 때(로그아웃·세션 종료·사용 중지·퇴사) 서명한 로그아웃 토큰을 받는다. `aud` = client_id, `sub` = subject ID, `events` 에 back-channel-logout, `typ: logout+jwt`(API 접근 토큰으로 쓸 수 없음). 로그인 세션 하나가 끝나면(로그아웃·관리자 세션 종료) 그 클라이언트에 준 ID 토큰의 `sid`(Spring Authorization Server 가 넣는 HTTP 세션 ID 해시, 저장된 ID 토큰 claim 에서 읽음)를 함께 넣어 받는 쪽이 그 세션만 끝내게 하고, 사용자 단위로 끝나면(사용 중지·잠금·퇴사) `sub` 만 넣어 그 사용자의 세션을 모두 끝내게 한다. discovery 에 `backchannel_logout_supported`·`backchannel_logout_session_supported` 를 알린다. 커밋 뒤 별도 스레드로 보내고 실패는 로그만 남긴다. HTTP/1.1 로 보낸다 (HTTP/2 기본값은 http:// 주소에 h2c 업그레이드 요청을 보내는데, Next.js 처럼 업그레이드를 직접 처리하는 서버는 연결을 끊는다) |
| 호출 수 제한 | IP 별 1분 구간: 로그인 POST 20, 토큰 120, 권한 판정 6000, 그 밖의 API 600 (`iam.rate-limit.*`). 기본은 서버별. `iam.rate-limit.store: jdbc` 면 로그인·토큰 경로를 `rate_limit_counter`(V12)에서 여러 서버가 함께 센다 (지난 구간은 만료 스케줄러가 지움). 운영은 `forward-headers-strategy: native` 로 내부 프록시가 준 실제 IP 를 쓴다 |
| API 키 | `iam_` 접두어 원문은 발급 때 한 번만 보여주고 hash 만 저장. 키로 들어온 요청은 키 소유 subject 로 판정 |

### HR 연동 규칙

`POST /api/v1/hr/sync?dryRun=true|false` (`HrSyncService`). 인사 시스템이 원본이고 키는 사번(`USER.emp_no`)이다. 외부 사용자(`user_kind = EXTERNAL`)는 사번이 없어 맞춰지지 않으며 연동이 건드리지 않는다.

| 항목 | 규칙 |
|---|---|
| 처리 단위 | 레코드마다 새 트랜잭션. 한 레코드가 실패(없는 조직 코드, 형식 오류, 직무 분리 위반 등)해도 그 레코드만 `ERROR` 로 돌려주고 나머지는 반영한다. 같은 사번이 피드에 두 번 오면 두 번째는 오류 |
| 미리보기 | `dryRun=true` 면 레코드마다 실제로 처리하고 DB 에 내보낸 뒤 롤백한다(제약 위반까지 드러남). 감사 기록·세션 회수도 함께 롤백된다. 레코드끼리는 서로의 결과를 보지 못한다 |
| 입사 | 처음 보는 사번 → 사용자 생성 + 주 소속(PRIMARY) 생성(→ 조직 역할 규칙 적용). **로그인 계정은 만들지 않는다** (따로 발급하거나 이후 SSO 로 연결). 처음 보는 사번이 이미 퇴사면 만들지 않는다(`SKIPPED`) |
| 정보 | 이름·이메일·전화·입사일이 다르면 고친다. 빈 선택 항목(이메일·전화·입사일·직위·직급·조직장 여부)은 "보내지 않음"으로 보고 기존 값을 둔다 |
| 이동 | 주 소속 조직이 다르면 `transferPrimary` → 전적(Mover) 처리 규칙 그대로. 직위·직급은 보내지 않았으면 이어받고, 조직장 여부는 보낸 값(없으면 아님)이다. 같은 조직이면 직위·직급·조직장 여부만 고친다(`MembershipUpdatedEvent` → `AUDIT_EVENT(MEMBERSHIP_CHANGE, SUBJECT_ORGANIZATION, UPDATE)`) |
| 휴직·복직 | `LEAVE` → `employment_status = LEAVE`, 사용 중이면 `DISABLED`(→ 세션·토큰·API 키 회수). `EMPLOYED` → `EMPLOYED`, `DISABLED` 면 `ACTIVE`. 잠김은 건드리지 않는다. **재직 상태의 원본은 인사 시스템이라, 연동 대상 사용자를 콘솔에서 "사용 중지"해도 다음 연동에서 재직이면 다시 사용된다** |
| 퇴사 | `RETIRED`(날짜 없으면 오늘)나 퇴사일이 오면 위 "퇴사"와 같이 처리하고, 미래 날짜면 예약한다. 예약이 있는데 퇴사일이 빠져 오면 예약을 취소한다(퇴사 철회). 이미 퇴사한 사용자는 그대로 둔다 |
| 피드에 없는 사람 | `reportMissing=true` 면 피드에 없는 `ACTIVE`·`DISABLED` 임직원(EMPLOYEE)을 알려준다(초기 관리자 사번 `iam.bootstrap.admin-emp-no`·외부 사용자 제외). **보고만 하고 퇴사시키지 않는다** |
| 결과 | 레코드마다 `CREATED`, `UPDATED`, `TRANSFERRED`, `MEMBERSHIP_UPDATED`, `ON_LEAVE`, `RETURNED`, `RETIRED`, `RETIRE_SCHEDULED`, `RETIRE_CANCELLED`, `SKIPPED`, `UNCHANGED`, `ERROR`(사유) 중 해당하는 것 |
| 실행 기록 | 실행마다(미리보기 포함) `hr_sync_run`(V14, ERD 외 테이블)에 결과별 건수, 오류 앞 100건, 피드에 없는 사용자 수를 남긴다. 개별 변경은 각 변경의 감사 기록에 남는다. `GET /api/v1/hr/sync-runs` 는 최근 50건 |
| 호출 | 리소스 `iam.identity.hrsync`(실행 EXECUTE·조회 READ). `iam.hr.sync` scope 의 client credentials 토큰이나, 기동 시 만드는 `IAM_HR_SYNC` 역할을 준 서비스 계정의 API 키 |

### webhook 규칙

`webhook_subscription`·`webhook_delivery`(V15, ERD 외 테이블). 구현은 `iam-app` 의 `com.didrakon.iam.webhook` (모든 모듈의 이벤트를 받으므로 app 에 둔다).

| 항목 | 규칙 |
|---|---|
| 아웃박스 | 도메인 이벤트 리스너(`WebhookOutbox`)가 업무 변경과 **같은 트랜잭션**에서 켜진 구독 중 유형이 맞는 것마다 `webhook_delivery(PENDING)` 를 쓴다. 업무 변경이 롤백되면 전달 행도 없다. HTTP 전송은 커밋된 행만 보고 트랜잭션 밖에서 한다 |
| 이벤트 | `user.status_changed`(subjectId, status) ← 사용자 상태 변경, `membership.changed`(subjectId, membershipId·orgId 또는 fromOrgId·toOrgId, change = JOINED/LEFT/UPDATED/TRANSFERRED) ← 소속 생성·종료·직위 변경·주 소속 이동, `group_membership.changed`(groupId, subjectId, change), `role_assignment.changed`(assignmentId, subjectId, roleId, scopeId, sourceType, changeType), `access_request.changed`(requestId, requestType, subjectId, roleId, status), `config.changed`(target, targetId, action) ← `AdminChangeEvent`, 위험 정책 변경(target `RISK_POLICY`), 접근 정책 버전 활성화(target `POLICY`, action `ACTIVATE_VERSION`, versionId), `organization.moved`(orgId, subtreeOrgIds) ← 조직 이동, `user.credential_changed`(subjectId, credentialType `PASSKEY`, change `ADDED`/`REMOVED`. 자격 증명 ID·이름은 넣지 않음) ← 패스키 등록·삭제, `access_review.changed`(campaignId, action `CREATE`/`ESCALATE`/`CLOSE`, itemCount) ← 접근 재검토 캠페인. 구독은 유형 배열이나 `["*"]`(전체). `webhook.test` 는 `POST /webhooks/{id}/test` 로 그 구독에만 넣는다 |
| 본문 | `{"id": 이벤트 UUID, "type", "occurredAt": ISO-8601, "data": {...}}`. data 에는 ID·상태 코드만 넣는다. 이름·연락처 등 개인정보와 설정 변경의 전후 값은 넣지 않으며, 받는 쪽이 필요하면 API 로 조회한다. 한 이벤트를 여러 구독에 보내면 `id` 가 같다 |
| 헤더 | `Content-Type: application/json`, `X-Didrakon-Event`(유형), `X-Didrakon-Delivery`(전달 ID), `X-Didrakon-Timestamp`(보낸 시각, epoch 초), `X-Didrakon-Signature` |
| 서명 | `sha256=` + hex(HMAC-SHA256(서명 비밀값, 타임스탬프 + `"."` + 본문)). 받는 쪽은 같은 값을 계산해 비교하고, 타임스탬프가 5분보다 오래됐으면 거부한다(재전송 공격 방지) |
| 비밀값 | `whsec_` 로 시작하는 무작위 값. 구독에는 `SecretStore` 참조(`secret_reference`)만 두고 원문은 추가·교체 응답에서 한 번만 준다. 조회 API·감사 기록에는 넣지 않는다. 교체하면 이전 값은 지워지고 다음 전송부터 새 값으로 서명한다 |
| 전달 | 전달 작업(`iam.webhook.interval`, 기본 10초, `iam.scheduling.enabled` 를 따르고 ShedLock `iam-webhook` 으로 한 인스턴스만)이 차례가 된 PENDING·FAILED 를 한 번에 최대 100건 POST 한다. 제한 시간 5초, redirect 는 따라가지 않는다. 2xx 면 SUCCEEDED |
| 순서 | 구독마다 만든 순서(전달 ID 순)로 보낸다. 끝나지 않은(PENDING·FAILED) 앞 전달이 있으면 뒤 전달은 기다리고, 앞 전달이 성공하면 같은 작업 안에서 다음 전달이 이어 나간다. 앞 전달이 계속 실패하면 DEAD 가 될 때까지(최대 약 7시간) 그 구독은 멈춘다. 다른 구독에는 영향이 없다. 다시 보내기로 되살린 예전 전달은 순서와 무관하게 다시 맨 앞이 된다 |
| 내부망 차단 (SSRF) | 등록·수정할 때와 **보낼 때마다** 주소를 풀어, 루프백·사설(10/8, 172.16/12, 192.168/16)·링크 로컬(169.254/16, 클라우드 메타데이터 포함)·CGNAT(100.64/10)·0/8·198.18/15·240/4·멀티캐스트·IPv6 ULA(fc00::/7)·링크 로컬이면 막는다. 전송은 Apache HttpClient 의 DNS 해석 단계에서 확인하고 **확인한 그 주소로만 접속**하므로, 확인과 접속 사이에 DNS 가 바뀌어도(DNS rebinding) 우회할 수 없다. 등록은 409, 전송은 실패(`BlockedAddressException`)로 남아 재시도 규칙을 따른다. 아직 풀리지 않는 이름은 등록은 받고 보낼 때 다시 본다. 로컬·테스트는 `iam.webhook.allow-private-network: true` 로 허용 (운영 기본 false) |
| 재시도 | 실패(2xx 아님·연결 오류·시간 초과)하면 FAILED 로 두고 30초·2분·10분·1시간·6시간 뒤 다시 보낸다. 6번째 실패면 DEAD(더 보내지 않음). 실패 사유는 상태 코드나 예외 종류만 남기고 응답 본문은 남기지 않는다. `POST /webhook-deliveries/{id}/redeliver` 는 상태와 관계없이 PENDING·시도 0 으로 되돌려 바로 보낸다 |
| 최소 한 번 | 받는 쪽 응답이 늦거나 저장 직전에 서버가 멈추면 같은 전달이 다시 갈 수 있다. 받는 쪽은 `X-Didrakon-Delivery`(전달 ID)나 본문 `id`(이벤트 ID)로 중복을 거른다 |
| 끄기 | 구독은 지우지 않고 끈다. 꺼진 구독에는 새 전달을 쓰지 않고, 남은 전달도 다시 켤 때까지 보내지 않는다. 추가·수정·켜기·끄기·비밀값 교체는 `AdminChangeEvent`(`WEBHOOK`) → `AUDIT_EVENT(POLICY_CHANGE)` |
| 권한 | 리소스 `iam.integration.webhook`(조회 READ, 추가 CREATE, 수정·켜기/끄기·교체·시험·다시 보내기 UPDATE) |

### 관리 변경 규칙

| 항목 | 규칙 |
|---|---|
| 지우지 않고 끈다 | 사용자·조직·그룹·역할·리소스·권한·범위·정책·직무 분리·SSO 클라이언트는 삭제하지 않고 `is_active`(사용자는 `status`)로 끈다. 감사 기록과 판정 로그가 이 행을 가리키기 때문이다 |
| 연결은 기간을 끝낸다 | 역할의 권한(`ROLE_PERMISSION.valid_until`), 정책 예외, 직무 분리 예외는 "지금"으로 기간을 끝내 회수한다. 이력은 남는다 |
| 바꿀 수 없는 값 | 코드(사번·역할·리소스 키·범위·정책 코드), 사용자 구분(EMPLOYEE·EXTERNAL), 권한의 행위·효과, 정책의 유형·효과, 범위의 유형·대상. 의미가 바뀌면 새로 만든다 |
| 끌 때 조건 | 조직은 구성원·사용 중인 하위 조직이 없어야, 그룹은 구성원이 없어야 끌 수 있다. 전체(GLOBAL) 범위와 관리 콘솔 클라이언트(`iam-admin`)는 끌 수 없다 |
| 효력 | 사용자: 로그인 불가 + PDP 가 거부(주체 상태 ACTIVE 만 통과). 역할·권한·리소스·범위·정책·직무 분리: PDP·부여 검사에서 빠진다. SSO 클라이언트: `client_id` 조회가 막혀 authorize·token 요청이 거부된다. 이미 발급된 토큰은 만료까지 남는다 |
| 감사 | 모든 변경은 `AdminChangeEvent` → `AUDIT_EVENT`(전후 값). 유형: 역할 ROLE_CHANGE, 리소스·권한·범위 PERMISSION_CHANGE, 사용자·조직·그룹 MEMBERSHIP_CHANGE, 정책·직무 분리·클라이언트 POLICY_CHANGE |

### 거버넌스 규칙 (governance)

| 항목 | 규칙 |
|---|---|
| 직무 분리 | 모든 부여 경로(직접·조직·그룹·JIT·위임)에서 충돌 역할을 이미 가진 subject 에게 부여하면 거부하고, 그 부여를 일으킨 변경(예: 소속 추가)까지 롤백한다. 유효한 `ROLE_CONFLICT_EXCEPTION` 이 있으면 허용. **비상 접근은 검사하지 않고** 감사 기록으로 남긴다. 충돌 정의 이전에 이미 두 역할을 가진 subject 는 그대로 둔다 |
| JIT | 사유 필수, 기간 최대 30일, 같은 역할 대기 요청 1건. 요청 시점에 직무 분리 위반을 먼저 거부. 승인되면 `ROLE_ASSIGNMENT(source_type=JIT, source_id=request_id)` 를 요청 기간으로 만든다 |
| 승인 조건 | `APPROVAL_POLICY` 중 역할의 role_type 이 같은 것 → role_type 이 빈 기본 정책 → 없으면 1명. 서로 다른 승인자 수, `require_security_team` = `SECURITY_TEAM` 그룹 구성원 1명 이상, `require_owner` = **요청자 PRIMARY 소속 조직의 관리자(is_manager)** 1명 이상. 본인 승인 불가. `resource_sensitivity` 는 아직 쓰지 않음 |
| 위임 | 위임자가 직접 가진(위임받지 않은) 같은 역할·scope 만. 재위임 불가. 위임 기간으로 `ROLE_ASSIGNMENT(DELEGATION)` 생성. 위임자가 그 역할을 잃으면(회수·만료) 위임도 자동 종료 |
| 비상 접근 | 정책별 사유·MFA·승인 요구. 승인이 필요 없으면 즉시, 필요하면 승인 후 최대 시간만큼 `ROLE_ASSIGNMENT(BREAK_GLASS)` 생성. 최대 24시간 |
| 만료 | 1분마다(`iam.scheduling`) 기간이 끝난 할당 → `EXPIRED`(이력 `change_type = EXPIRE`), 대기 요청 → `EXPIRED`, 위임·비상 접근 상태 갱신. 판정은 기간으로 이미 걸러내므로 상태·이력 정리 작업이다. 여러 인스턴스에서는 ShedLock(`shedlock` 테이블, V8)으로 한 인스턴스만 실행한다 |
| 접근 요청 위험 | 요청의 `risk_level` 은 역할 성격(특권 HIGH, 민감 MEDIUM, 그 외 LOW)과 위험 평가(JIT·비상 접근은 PRIVILEGE) 중 높은 쪽. 평가는 `RISK_ASSESSMENT.request_id` 로 요청에 연결해 남긴다 |

### 접근 재검토 규칙

`access_review_campaign`·`access_review_item`(V16, ERD 외 테이블). 구현은 `com.didrakon.iam.governance.review`. 개인정보보호법의 접근 권한 정기 점검을 증적과 함께 남기기 위한 것이다.

| 항목 | 규칙 |
|---|---|
| 대상 | 시작 시점에 효력이 있는 할당을 항목으로 스냅샷한다. 범위: 전체, 조직(그 조직 — 하위 포함 선택 — 을 **PRIMARY 소속**으로 둔 사람), 역할. 조건: 특권 역할만(`is_privileged`), 출처(기본 `DIRECT`·`JIT`·`DELEGATION`, `BREAK_GLASS` 선택). 대상이 하나도 없으면 시작하지 않는다 |
| 출처 제한 | `ORGANIZATION`·`GROUP` 할당은 넣을 수 없다. 개별 회수 경로가 없고 회수해도 동기화가 다시 만들기 때문에, 조직·그룹 역할 규칙을 바꿔 검토한다. `SYSTEM` 도 대상이 아니다 |
| 재검토 표시 | `review_required`(전적 등) 할당은 범위(조직·역할) 안이면 출처·특권 조건과 관계없이 넣는다. 이미 담당자 확인이 필요하다고 표시된 할당이기 때문이다 |
| 스냅샷 | 항목에 대상자 이름·사번·주 소속 조직, 역할 코드·이름·특권 여부, 범위 이름, 검토자 이름, 할당 기간, 재검토 표시를 함께 저장한다. 기준 데이터가 나중에 바뀌어도 그때 무엇을 검토했는지 보여준다 |
| 검토자 | 대상자 PRIMARY 소속 조직의 관리자(`is_manager`, 소속 유형 무관) 중 subject ID 가 가장 작은 사람. 본인은 제외. 없으면 비워 두고 관리자(`iam.governance.review` APPROVE)가 정한다. 대상자가 관리 콘솔 권한을 가졌거나 곧 받을 사람이면 조직장에게 맡기지 않고 비워 둔다(이관도 안 함, 검토자 결정도 거부) — `is_manager` 는 조직 단위 관리자가 바꿀 수 있어서다 |
| 결정 | 유지(KEEP)·회수(REVOKE)와 선택 의견. 본인 할당은 검토할 수 없다. 검토자는 `/me` 로 자기에게 배정된 항목만(다른 항목은 404), 관리자는 모든 항목을 정한다. 이미 정한 항목·닫힌 캠페인은 바꿀 수 없다 |
| 회수 | 바로 회수한다. `DIRECT` 는 직접 회수, `JIT` 는 출처(요청) 단위 회수, `DELEGATION` 은 위임 회수(위임도 `REVOKED`), `BREAK_GLASS` 는 비상 접근 종료. 이미 끝난(회수·만료·기간 경과) 할당은 회수할 것이 없으므로 결정만 남긴다 |
| 유지 | 할당의 재검토 표시를 지우고 역할 변경 이력에 `REVIEW` 로 남긴다 (표시가 없으면 할당은 그대로) |
| 상위 관리자 이관 | 캠페인에 `escalation_days`(1~30, V19)를 넣으면 기한이 지났을 때 바로 닫지 않고, 미결정 항목을 대상자 PRIMARY 소속 조직의 **상위 조직부터 올라가며** 찾은 첫 관리자(본인·지금 검토자 제외, subject ID 가 가장 작은 사람)에게 넘긴다. 관리자가 없는 중간 조직은 건너뛰고, 끝까지 없으면 그대로 둔다(관리자가 검토). 원래 검토자는 `escalated_from_id`·`escalated_from_name`·`escalated_at` 으로 남고 원래 검토자의 할 일에서는 빠진다. 감사 `REVIEW_CAMPAIGN_ESCALATE`(넘긴 항목 수). 그 뒤 `due_at + escalation_days` 가 지나면 아래처럼 닫는다. 스케줄러가 최종 기한 뒤에 처음 돌면 그 실행에서 이관하고 다음 실행에서 닫는다 |
| 기한·마감 | 만료 스케줄러가 기한(이관하는 캠페인은 최종 기한)이 지난 열린 캠페인을 캠페인마다 새 트랜잭션으로 닫는다. 남은 항목에 `on_overdue`(유지·회수)를 적용하고 결정자는 비워 둔다(의견 "기한 경과"). 관리자가 기한 전에 마감해도 같다(의견 "마감 시 미결정"). **자동 유지는 사람이 확인한 것이 아니므로 재검토 표시를 지우지 않는다** |
| 증적 | `GET /api/v1/access-reviews/{id}/export` 는 항목·검토자·이관 전 검토자·결정·결정자·시각(KST)·의견을 CSV(UTF-8 BOM, Excel 용)로 준다. `=`·`+`·`-`·`@` 로 시작하는 값은 앞에 `'` 를 붙여 수식으로 실행되지 않게 한다 |
| 권한 | 리소스 `iam.governance.review`(조회·내보내기 READ, 시작 CREATE, 관리자 결정·마감 APPROVE). 검토자 본인 화면은 `@SelfService` |

### 위험 규칙 (risk)

| 항목 | 규칙 |
|---|---|
| 정책 | `RISK_POLICY` 의 `risk_type` 이 같은 활성 정책만 평가한다. `condition_expression` 은 `{"signal": "<신호>", ...}`. 기본 정책은 V9. V13 이 기본 로그인 정책 중 `NEW_DEVICE`·`FAILED_LOGIN_BURST` 의 조치를 ALLOW(점수만)로 낮췄다 — 흔한 신호라 단독으로 추가 인증을 요구하면 MFA 없는 사용자가 영구 차단되기 때문이며, 운영자가 고친 정책은 그대로 둔다. 해외 IP(`FOREIGN_IP`)만 CHALLENGE. V9 머리 주석("CHALLENGE 는 기록만")은 V13 으로 대체된다 |
| 신호 | `NEW_DEVICE`(이 User-Agent 로 로그인한 적 없음), `UNUSUAL_TIME`(`from`~`to` 밖, 기본 07:00~22:00 KST), `FAILED_LOGIN_BURST`(직전 연속 실패 ≥ `threshold`), `MASS_ACCESS`(`windowSeconds` 동안 권한 판정 ≥ `threshold`), `FOREIGN_IP`(`allowedCountries` 밖. 국가는 `iam.risk.ip-country-overrides` 의 CIDR 대역 → `iam.risk.geoip-database` 의 MaxMind Country DB 순으로 찾는다. 둘 다 없거나 사설·루프백 주소·찾지 못한 주소면 신호 없음) |
| 점수·조치 | 잡힌 정책 점수의 합(최대 100). 조치는 그중 가장 강한 것(ALLOW < CHALLENGE < APPROVAL < DENY). 합이 80 이상이면 DENY. 수준: 80+ CRITICAL, 50+ HIGH, 20+ MEDIUM |
| 기록 | 신호가 하나라도 있으면 `RISK_SIGNAL`·`RISK_ASSESSMENT` 를 남긴다. 접근 요청 평가는 늘 남긴다 |
| 관리 | 정책 이름·조건·점수·조치는 고칠 수 있고 `risk_type` 은 못 바꾼다(새 정책으로). 조건은 저장 전에 엔진이 읽을 수 있는지 검사한다(signal 값, from·to 는 HH:mm, threshold·windowSeconds 는 1 이상 정수, allowedCountries 는 문자열 배열). 삭제 대신 끈다. 추가·수정·켜기·끄기는 `AUDIT_EVENT(POLICY_CHANGE, resource_type = RISK_POLICY)` 에 전후 값과 함께 남는다 |
| 쓰는 곳 | 로그인: DENY 는 막는다. CHALLENGE·APPROVAL 은 추가 인증 — 확인된 TOTP 가 있으면 MFA 단계(인증 이벤트 `LOGIN/CHALLENGE`), 없으면 막는다(`LOGIN/FAILURE`, `RISK_CHALLENGE_NO_MFA`, 실패 횟수는 그대로. `iam.risk.block-challenge-without-mfa=false` 면 기록만). 권한 판정: RBAC 이 허용하면 DATA_ACCESS 점수를 `CONTEXT.riskScore` 로 넣고 `AUTHORIZATION_LOG.risk_score` 에 남긴다. 점수만으로 막지 않으며, 막으려면 riskScore 를 보는 ABAC 정책을 둔다. 접근 요청: 위 거버넌스 규칙 |

## 5. 결정 사항

설계 중 확인이 필요했던 항목의 결정 결과입니다. (2026-11-03 확정)

1. **JIT·위임은 역할 단위로만 허용.** 원본은 단일 권한(permission)도 요청·위임할 수 있었으나, `ROLE_ASSIGNMENT` 단일 경로를 유지하려고 역할 단위로 제한합니다. 단일 권한이 필요하면 그 권한만 가진 역할을 정의합니다.
2. **`PERMISSION_LINEAGE` 삭제.** 권한 출처는 `ROLE_ASSIGNMENT(source_type, source_id)` + `ROLE_PERMISSION` 조인으로 계산합니다. 사용자당 권한 조회가 느려지면 캐시나 파생 테이블로 다시 도입합니다.
3. **SAS 토큰은 SHA-256 hash로 저장.** SAS는 Spring Security 7.1.2에 포함된 버전이며, 기본 `JdbcOAuth2AuthorizationService`는 code·token 값을 평문 `BLOB`으로 저장하고 `refresh_token_value = ?` 같은 인덱스 없는 비교로 조회합니다. 커스텀 `OAuth2AuthorizationService`로 hash를 저장·조회하고 `VARCHAR(64)` 인덱스를 둡니다. refresh token은 회전(rotation) 방식만 사용합니다.
4. **`POLICY.priority`와 `ROLE.priority` 유지.** deny-overrides에서는 판정에 영향이 없으며 관리 콘솔 표시 순서·설명용입니다. 판정 로직에서 이 값을 읽지 않습니다.
