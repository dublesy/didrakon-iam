-- authz: 리소스·관계(ReBAC), scope, 역할·권한(RBAC), 역할 할당(판정 단일 경로), 조직·그룹 역할 규칙, 정책(ABAC), 판정 로그

CREATE TABLE resource (
    resource_id        BIGINT        NOT NULL AUTO_INCREMENT,
    client_id          BIGINT        NOT NULL,
    parent_resource_id BIGINT        NULL,
    resource_key       VARCHAR(200)  NOT NULL,
    resource_name      VARCHAR(200)  NOT NULL,
    resource_type      VARCHAR(30)   NOT NULL COMMENT 'SYSTEM, MENU, API, DATA, BUTTON, DOCUMENT',
    resource_path      VARCHAR(1000) NULL,
    sensitivity        VARCHAR(30)   NOT NULL COMMENT 'PUBLIC, INTERNAL, CONFIDENTIAL, SECRET',
    is_active          BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at         DATETIME(6)   NOT NULL,
    PRIMARY KEY (resource_id),
    UNIQUE KEY uk_resource_client_key (client_id, resource_key),
    CONSTRAINT fk_resource_client FOREIGN KEY (client_id) REFERENCES sso_client (client_id),
    CONSTRAINT fk_resource_parent FOREIGN KEY (parent_resource_id) REFERENCES resource (resource_id)
);

CREATE TABLE relation_type (
    relation_type_id BIGINT        NOT NULL AUTO_INCREMENT,
    relation_code    VARCHAR(100)  NOT NULL COMMENT 'OWNS, MANAGES, APPROVES, BELONGS_TO, MEMBER_OF, ASSIGNED_TO',
    relation_name    VARCHAR(200)  NOT NULL,
    description      VARCHAR(1000) NULL,
    PRIMARY KEY (relation_type_id),
    UNIQUE KEY uk_relation_type_code (relation_code)
);

CREATE TABLE resource_relation (
    resource_relation_id BIGINT      NOT NULL AUTO_INCREMENT,
    source_resource_id   BIGINT      NOT NULL,
    relation_type_id     BIGINT      NOT NULL,
    target_resource_id   BIGINT      NOT NULL,
    valid_from           DATETIME(6) NOT NULL,
    valid_until          DATETIME(6) NULL,
    PRIMARY KEY (resource_relation_id),
    KEY idx_resource_relation_source (source_resource_id, relation_type_id),
    KEY idx_resource_relation_target (target_resource_id, relation_type_id),
    CONSTRAINT fk_resource_relation_source FOREIGN KEY (source_resource_id) REFERENCES resource (resource_id),
    CONSTRAINT fk_resource_relation_type FOREIGN KEY (relation_type_id) REFERENCES relation_type (relation_type_id),
    CONSTRAINT fk_resource_relation_target FOREIGN KEY (target_resource_id) REFERENCES resource (resource_id)
);

CREATE TABLE subject_relation (
    subject_relation_id BIGINT      NOT NULL AUTO_INCREMENT,
    subject_id          BIGINT      NOT NULL,
    relation_type_id    BIGINT      NOT NULL,
    target_subject_id   BIGINT      NULL,
    target_resource_id  BIGINT      NULL,
    valid_from          DATETIME(6) NOT NULL,
    valid_until         DATETIME(6) NULL,
    PRIMARY KEY (subject_relation_id),
    KEY idx_subject_relation_subject (subject_id, relation_type_id),
    CONSTRAINT fk_subject_relation_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_subject_relation_type FOREIGN KEY (relation_type_id) REFERENCES relation_type (relation_type_id),
    CONSTRAINT fk_subject_relation_target_subject FOREIGN KEY (target_subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_subject_relation_target_resource FOREIGN KEY (target_resource_id) REFERENCES resource (resource_id),
    CONSTRAINT ck_subject_relation_one_target
        CHECK ((target_subject_id IS NOT NULL) + (target_resource_id IS NOT NULL) = 1)
);

CREATE TABLE scope (
    scope_id            BIGINT       NOT NULL AUTO_INCREMENT,
    scope_code          VARCHAR(100) NOT NULL,
    scope_name          VARCHAR(200) NOT NULL,
    scope_type          VARCHAR(30)  NOT NULL COMMENT 'GLOBAL, ORGANIZATION, RESOURCE, PROJECT, DATA',
    org_id              BIGINT       NULL,
    resource_id         BIGINT       NULL,
    parent_scope_id     BIGINT       NULL,
    scope_expression    JSON         NULL,
    include_descendants BOOLEAN      NOT NULL DEFAULT FALSE COMMENT '하위 조직·리소스 포함',
    is_active           BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (scope_id),
    UNIQUE KEY uk_scope_code (scope_code),
    CONSTRAINT fk_scope_org FOREIGN KEY (org_id) REFERENCES organization (org_id),
    CONSTRAINT fk_scope_resource FOREIGN KEY (resource_id) REFERENCES resource (resource_id),
    CONSTRAINT fk_scope_parent FOREIGN KEY (parent_scope_id) REFERENCES scope (scope_id)
);

-- scope 미지정 부여는 이 행을 참조한다 (ROLE_PERMISSION, ROLE_ASSIGNMENT 의 scope_id NOT NULL). 코드에서는 scope_code 로 찾는다
INSERT INTO scope (scope_code, scope_name, scope_type, include_descendants, is_active)
VALUES ('GLOBAL', '전체', 'GLOBAL', TRUE, TRUE);

CREATE TABLE data_scope (
    data_scope_id         BIGINT      NOT NULL AUTO_INCREMENT,
    scope_id              BIGINT      NOT NULL,
    data_type             VARCHAR(30) NOT NULL COMMENT 'EMPLOYEE, PAYROLL, CUSTOMER, CONTRACT',
    condition_expression  JSON        NULL,
    masking_policy        JSON        NULL,
    row_filter_expression JSON        NULL,
    PRIMARY KEY (data_scope_id),
    CONSTRAINT fk_data_scope_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE role (
    role_id       BIGINT       NOT NULL AUTO_INCREMENT,
    role_code     VARCHAR(100) NOT NULL,
    role_name     VARCHAR(200) NOT NULL,
    role_type     VARCHAR(30)  NOT NULL COMMENT 'SYSTEM, BUSINESS, CUSTOM, PRIVILEGED',
    priority      INT          NOT NULL DEFAULT 0 COMMENT '표시 순서·설명용, 판정 결과에는 영향 없음',
    is_sensitive  BOOLEAN      NOT NULL DEFAULT FALSE,
    is_privileged BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at    DATETIME(6)  NOT NULL,
    updated_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (role_id),
    UNIQUE KEY uk_role_code (role_code)
);

CREATE TABLE permission (
    permission_id   BIGINT       NOT NULL AUTO_INCREMENT,
    permission_code VARCHAR(100) NOT NULL,
    permission_name VARCHAR(200) NOT NULL,
    resource_id     BIGINT       NOT NULL,
    action          VARCHAR(30)  NOT NULL COMMENT 'READ, CREATE, UPDATE, DELETE, EXECUTE, APPROVE, EXPORT',
    effect          VARCHAR(30)  NOT NULL COMMENT 'ALLOW, DENY',
    is_sensitive    BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (permission_id),
    UNIQUE KEY uk_permission_code (permission_code),
    KEY idx_permission_resource_action (resource_id, action),
    CONSTRAINT fk_permission_resource FOREIGN KEY (resource_id) REFERENCES resource (resource_id)
);

CREATE TABLE role_permission (
    role_permission_id BIGINT      NOT NULL AUTO_INCREMENT,
    role_id            BIGINT      NOT NULL,
    permission_id      BIGINT      NOT NULL,
    scope_id           BIGINT      NOT NULL COMMENT '미지정 시 GLOBAL scope',
    valid_from         DATETIME(6) NOT NULL,
    valid_until        DATETIME(6) NULL,
    PRIMARY KEY (role_permission_id),
    UNIQUE KEY uk_role_permission (role_id, permission_id, scope_id),
    CONSTRAINT fk_role_permission_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_role_permission_permission FOREIGN KEY (permission_id) REFERENCES permission (permission_id),
    CONSTRAINT fk_role_permission_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE role_assignment (
    assignment_id   BIGINT        NOT NULL AUTO_INCREMENT,
    subject_id      BIGINT        NOT NULL,
    role_id         BIGINT        NOT NULL,
    scope_id        BIGINT        NOT NULL COMMENT '미지정 시 GLOBAL scope',
    source_type     VARCHAR(30)   NOT NULL COMMENT 'DIRECT, GROUP, ORGANIZATION, JIT, DELEGATION, BREAK_GLASS, SYSTEM',
    source_id       BIGINT        NULL COMMENT '출처 행 ID (논리 참조). DIRECT, SYSTEM 은 NULL',
    valid_from      DATETIME(6)   NOT NULL,
    valid_until     DATETIME(6)   NULL,
    status          VARCHAR(30)   NOT NULL COMMENT 'ACTIVE, EXPIRED, REVOKED',
    review_required BOOLEAN       NOT NULL DEFAULT FALSE COMMENT '전적 등으로 재검토 필요',
    assigned_by     BIGINT        NULL,
    reason          VARCHAR(1000) NULL,
    revoked_at      DATETIME(6)   NULL,
    revoked_by      BIGINT        NULL,
    created_at      DATETIME(6)   NOT NULL,
    PRIMARY KEY (assignment_id),
    KEY idx_role_assignment_subject_status (subject_id, status),
    KEY idx_role_assignment_source (source_type, source_id),
    CONSTRAINT fk_role_assignment_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_role_assignment_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_role_assignment_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id),
    CONSTRAINT fk_role_assignment_assigned_by FOREIGN KEY (assigned_by) REFERENCES subject (subject_id),
    CONSTRAINT fk_role_assignment_revoked_by FOREIGN KEY (revoked_by) REFERENCES subject (subject_id)
);

CREATE TABLE organization_role (
    org_role_id          BIGINT      NOT NULL AUTO_INCREMENT,
    org_id               BIGINT      NOT NULL,
    role_id              BIGINT      NOT NULL,
    scope_id             BIGINT      NOT NULL COMMENT '생성될 ROLE_ASSIGNMENT 의 scope',
    apply_to_descendants BOOLEAN     NOT NULL DEFAULT FALSE COMMENT '하위 조직 구성원에게도 부여',
    is_active            BOOLEAN     NOT NULL DEFAULT TRUE,
    valid_from           DATETIME(6) NOT NULL,
    valid_until          DATETIME(6) NULL,
    PRIMARY KEY (org_role_id),
    KEY idx_organization_role_org (org_id),
    CONSTRAINT fk_organization_role_org FOREIGN KEY (org_id) REFERENCES organization (org_id),
    CONSTRAINT fk_organization_role_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_organization_role_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE group_role (
    group_role_id BIGINT      NOT NULL AUTO_INCREMENT,
    group_id      BIGINT      NOT NULL,
    role_id       BIGINT      NOT NULL,
    scope_id      BIGINT      NOT NULL COMMENT '생성될 ROLE_ASSIGNMENT 의 scope',
    valid_from    DATETIME(6) NOT NULL,
    valid_until   DATETIME(6) NULL,
    PRIMARY KEY (group_role_id),
    KEY idx_group_role_group (group_id),
    CONSTRAINT fk_group_role_group FOREIGN KEY (group_id) REFERENCES user_group (group_id),
    CONSTRAINT fk_group_role_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_group_role_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE policy (
    policy_id   BIGINT       NOT NULL AUTO_INCREMENT,
    policy_code VARCHAR(100) NOT NULL,
    policy_name VARCHAR(200) NOT NULL,
    policy_type VARCHAR(30)  NOT NULL COMMENT 'AUTHORIZATION, SECURITY, DATA, RISK',
    effect      VARCHAR(30)  NOT NULL COMMENT 'ALLOW, DENY, CHALLENGE, REQUIRE_APPROVAL',
    priority    INT          NOT NULL DEFAULT 0 COMMENT '표시 순서·설명용, 판정 결과에는 영향 없음',
    is_active   BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at  DATETIME(6)  NOT NULL,
    updated_at  DATETIME(6)  NOT NULL,
    PRIMARY KEY (policy_id),
    UNIQUE KEY uk_policy_code (policy_code)
);

CREATE TABLE policy_version (
    policy_version_id BIGINT        NOT NULL AUTO_INCREMENT,
    policy_id         BIGINT        NOT NULL,
    version           INT           NOT NULL,
    status            VARCHAR(30)   NOT NULL COMMENT 'DRAFT, ACTIVE, RETIRED. 정책당 ACTIVE 1개 (서비스 검증)',
    change_reason     VARCHAR(1000) NULL,
    created_by        BIGINT        NULL,
    created_at        DATETIME(6)   NOT NULL,
    PRIMARY KEY (policy_version_id),
    UNIQUE KEY uk_policy_version (policy_id, version),
    CONSTRAINT fk_policy_version_policy FOREIGN KEY (policy_id) REFERENCES policy (policy_id),
    CONSTRAINT fk_policy_version_created_by FOREIGN KEY (created_by) REFERENCES subject (subject_id)
);

CREATE TABLE policy_rule (
    rule_id           BIGINT       NOT NULL AUTO_INCREMENT,
    policy_version_id BIGINT       NOT NULL,
    rule_group        INT          NOT NULL COMMENT '같은 그룹은 AND, 그룹 간은 OR',
    attribute_source  VARCHAR(30)  NOT NULL COMMENT 'SUBJECT, RESOURCE, CONTEXT, RELATION, SESSION',
    attribute_name    VARCHAR(200) NOT NULL,
    operator          VARCHAR(30)  NOT NULL COMMENT 'EQ, NE, IN, NOT_IN, GT, LT, BETWEEN, MATCH, EXISTS',
    attribute_value   JSON         NULL COMMENT 'EXISTS 는 값 없음',
    rule_order        INT          NOT NULL DEFAULT 0,
    PRIMARY KEY (rule_id),
    KEY idx_policy_rule_version (policy_version_id, rule_group),
    CONSTRAINT fk_policy_rule_version FOREIGN KEY (policy_version_id) REFERENCES policy_version (policy_version_id)
);

CREATE TABLE policy_target (
    policy_target_id BIGINT NOT NULL AUTO_INCREMENT,
    policy_id        BIGINT NOT NULL,
    permission_id    BIGINT NULL,
    resource_id      BIGINT NULL,
    role_id          BIGINT NULL,
    PRIMARY KEY (policy_target_id),
    KEY idx_policy_target_policy (policy_id),
    CONSTRAINT fk_policy_target_policy FOREIGN KEY (policy_id) REFERENCES policy (policy_id),
    CONSTRAINT fk_policy_target_permission FOREIGN KEY (permission_id) REFERENCES permission (permission_id),
    CONSTRAINT fk_policy_target_resource FOREIGN KEY (resource_id) REFERENCES resource (resource_id),
    CONSTRAINT fk_policy_target_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT ck_policy_target_one_target
        CHECK ((permission_id IS NOT NULL) + (resource_id IS NOT NULL) + (role_id IS NOT NULL) = 1)
);

CREATE TABLE policy_exception (
    exception_id BIGINT        NOT NULL AUTO_INCREMENT,
    policy_id    BIGINT        NOT NULL,
    subject_id   BIGINT        NULL,
    resource_id  BIGINT        NULL,
    reason       VARCHAR(1000) NOT NULL,
    valid_from   DATETIME(6)   NOT NULL,
    valid_until  DATETIME(6)   NULL,
    PRIMARY KEY (exception_id),
    KEY idx_policy_exception_policy (policy_id),
    CONSTRAINT fk_policy_exception_policy FOREIGN KEY (policy_id) REFERENCES policy (policy_id),
    CONSTRAINT fk_policy_exception_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_policy_exception_resource FOREIGN KEY (resource_id) REFERENCES resource (resource_id),
    -- 대상 없는 예외는 정책 전체를 무력화하므로 금지한다
    CONSTRAINT ck_policy_exception_has_target CHECK (subject_id IS NOT NULL OR resource_id IS NOT NULL)
);

-- 대량 적재 테이블: 물리 FK 없음. 월 단위 RANGE 파티셔닝이 가능하도록 PK 에 decided_at 을 포함한다
CREATE TABLE authorization_log (
    authorization_log_id  BIGINT        NOT NULL AUTO_INCREMENT,
    trace_id              VARCHAR(64)   NULL,
    subject_id            BIGINT        NOT NULL,
    resource_id           BIGINT        NULL,
    action                VARCHAR(30)   NOT NULL,
    scope_id              BIGINT        NULL,
    session_id            BIGINT        NULL,
    context               JSON          NULL,
    decision              VARCHAR(30)   NOT NULL COMMENT 'ALLOW, DENY, CHALLENGE, REQUIRE_APPROVAL',
    decision_reason       VARCHAR(1000) NULL,
    matched_policy_id     BIGINT        NULL,
    matched_role_id       BIGINT        NULL,
    matched_permission_id BIGINT        NULL,
    matched_assignment_id BIGINT        NULL,
    matched_relation_id   BIGINT        NULL,
    risk_score            INT           NULL,
    explanation           JSON          NULL COMMENT '판정 근거 목록',
    evaluation_time_ms    INT           NULL,
    decided_at            DATETIME(6)   NOT NULL,
    PRIMARY KEY (authorization_log_id, decided_at),
    KEY idx_authorization_log_subject (subject_id, decided_at),
    KEY idx_authorization_log_trace (trace_id)
);
