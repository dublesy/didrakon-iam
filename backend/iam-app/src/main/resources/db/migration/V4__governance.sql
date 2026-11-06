-- governance: 접근 요청(JIT·Break-glass 공용)과 승인, 직무 분리(SoD), 위임, Break-glass

CREATE TABLE access_request (
    request_id      BIGINT        NOT NULL AUTO_INCREMENT,
    request_type    VARCHAR(30)   NOT NULL COMMENT 'JIT, BREAK_GLASS',
    subject_id      BIGINT        NOT NULL,
    role_id         BIGINT        NOT NULL COMMENT '역할 단위로만 요청 (ERD 결정 사항 1)',
    scope_id        BIGINT        NOT NULL,
    reason          VARCHAR(1000) NOT NULL,
    risk_level      VARCHAR(30)   NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    requested_start DATETIME(6)   NOT NULL,
    requested_end   DATETIME(6)   NOT NULL,
    status          VARCHAR(30)   NOT NULL COMMENT 'PENDING, APPROVED, REJECTED, EXPIRED, CANCELLED',
    created_at      DATETIME(6)   NOT NULL,
    PRIMARY KEY (request_id),
    KEY idx_access_request_subject_status (subject_id, status),
    CONSTRAINT fk_access_request_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_access_request_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_access_request_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE approval_policy (
    approval_policy_id      BIGINT       NOT NULL AUTO_INCREMENT,
    policy_name             VARCHAR(200) NOT NULL,
    resource_sensitivity    VARCHAR(30)  NULL COMMENT 'PUBLIC, INTERNAL, CONFIDENTIAL, SECRET',
    role_type               VARCHAR(30)  NULL COMMENT 'SYSTEM, BUSINESS, CUSTOM, PRIVILEGED',
    required_approval_count INT          NOT NULL DEFAULT 1,
    require_security_team   BOOLEAN      NOT NULL DEFAULT FALSE,
    require_owner           BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active               BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (approval_policy_id)
);

CREATE TABLE approval (
    approval_id        BIGINT        NOT NULL AUTO_INCREMENT,
    request_id         BIGINT        NOT NULL,
    approver_id        BIGINT        NOT NULL,
    approval_policy_id BIGINT        NULL,
    approval_step      INT           NOT NULL DEFAULT 1,
    status             VARCHAR(30)   NOT NULL COMMENT 'PENDING, APPROVED, REJECTED, SKIPPED',
    comment            VARCHAR(1000) NULL,
    decided_at         DATETIME(6)   NULL,
    PRIMARY KEY (approval_id),
    KEY idx_approval_request (request_id, approval_step),
    KEY idx_approval_approver_status (approver_id, status),
    CONSTRAINT fk_approval_request FOREIGN KEY (request_id) REFERENCES access_request (request_id),
    CONSTRAINT fk_approval_approver FOREIGN KEY (approver_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_approval_policy FOREIGN KEY (approval_policy_id) REFERENCES approval_policy (approval_policy_id)
);

CREATE TABLE role_conflict (
    conflict_id   BIGINT        NOT NULL AUTO_INCREMENT,
    role_id_a     BIGINT        NOT NULL,
    role_id_b     BIGINT        NOT NULL,
    conflict_type VARCHAR(30)   NOT NULL DEFAULT 'MUTUAL_EXCLUSION' COMMENT 'MUTUAL_EXCLUSION',
    severity      VARCHAR(30)   NOT NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    description   VARCHAR(1000) NULL,
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    PRIMARY KEY (conflict_id),
    UNIQUE KEY uk_role_conflict_pair (role_id_a, role_id_b),
    KEY idx_role_conflict_role_b (role_id_b),
    CONSTRAINT fk_role_conflict_role_a FOREIGN KEY (role_id_a) REFERENCES role (role_id),
    CONSTRAINT fk_role_conflict_role_b FOREIGN KEY (role_id_b) REFERENCES role (role_id),
    -- (A,B)와 (B,A) 중복을 막기 위해 항상 작은 ID 를 a 에 둔다
    CONSTRAINT ck_role_conflict_order CHECK (role_id_a < role_id_b)
);

CREATE TABLE role_conflict_exception (
    exception_id BIGINT        NOT NULL AUTO_INCREMENT,
    conflict_id  BIGINT        NOT NULL,
    subject_id   BIGINT        NOT NULL,
    approved_by  BIGINT        NOT NULL,
    reason       VARCHAR(1000) NOT NULL,
    valid_from   DATETIME(6)   NOT NULL,
    valid_until  DATETIME(6)   NULL,
    is_active    BOOLEAN       NOT NULL DEFAULT TRUE,
    PRIMARY KEY (exception_id),
    KEY idx_role_conflict_exception_subject (subject_id),
    CONSTRAINT fk_role_conflict_exception_conflict FOREIGN KEY (conflict_id) REFERENCES role_conflict (conflict_id),
    CONSTRAINT fk_role_conflict_exception_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_role_conflict_exception_approved_by FOREIGN KEY (approved_by) REFERENCES subject (subject_id)
);

CREATE TABLE delegation (
    delegation_id BIGINT        NOT NULL AUTO_INCREMENT,
    delegator_id  BIGINT        NOT NULL,
    delegate_id   BIGINT        NOT NULL,
    role_id       BIGINT        NOT NULL COMMENT '역할 단위로만 위임 (ERD 결정 사항 1)',
    scope_id      BIGINT        NOT NULL,
    start_time    DATETIME(6)   NOT NULL,
    end_time      DATETIME(6)   NOT NULL,
    reason        VARCHAR(1000) NOT NULL,
    status        VARCHAR(30)   NOT NULL COMMENT 'PENDING, ACTIVE, EXPIRED, REVOKED',
    created_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (delegation_id),
    KEY idx_delegation_delegate_status (delegate_id, status),
    CONSTRAINT fk_delegation_delegator FOREIGN KEY (delegator_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_delegation_delegate FOREIGN KEY (delegate_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_delegation_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_delegation_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE break_glass_policy (
    break_glass_policy_id BIGINT       NOT NULL AUTO_INCREMENT,
    policy_name           VARCHAR(200) NOT NULL,
    role_id               BIGINT       NOT NULL,
    scope_id              BIGINT       NOT NULL,
    require_reason        BOOLEAN      NOT NULL DEFAULT TRUE,
    require_approval      BOOLEAN      NOT NULL DEFAULT FALSE,
    require_mfa           BOOLEAN      NOT NULL DEFAULT TRUE,
    max_duration_minutes  INT          NOT NULL,
    is_active             BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (break_glass_policy_id),
    CONSTRAINT fk_break_glass_policy_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_break_glass_policy_scope FOREIGN KEY (scope_id) REFERENCES scope (scope_id)
);

CREATE TABLE break_glass_session (
    break_glass_session_id BIGINT        NOT NULL AUTO_INCREMENT,
    break_glass_policy_id  BIGINT        NOT NULL,
    subject_id             BIGINT        NOT NULL,
    request_id             BIGINT        NULL COMMENT '승인 필요 시',
    assignment_id          BIGINT        NULL COMMENT '생성된 ROLE_ASSIGNMENT',
    reason                 VARCHAR(1000) NULL,
    start_time             DATETIME(6)   NOT NULL,
    end_time               DATETIME(6)   NOT NULL,
    status                 VARCHAR(30)   NOT NULL COMMENT 'ACTIVE, EXPIRED, REVOKED',
    revoked_by             BIGINT        NULL,
    PRIMARY KEY (break_glass_session_id),
    UNIQUE KEY uk_break_glass_session_request (request_id),
    UNIQUE KEY uk_break_glass_session_assignment (assignment_id),
    KEY idx_break_glass_session_subject_status (subject_id, status),
    CONSTRAINT fk_break_glass_session_policy FOREIGN KEY (break_glass_policy_id) REFERENCES break_glass_policy (break_glass_policy_id),
    CONSTRAINT fk_break_glass_session_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_break_glass_session_request FOREIGN KEY (request_id) REFERENCES access_request (request_id),
    CONSTRAINT fk_break_glass_session_assignment FOREIGN KEY (assignment_id) REFERENCES role_assignment (assignment_id),
    CONSTRAINT fk_break_glass_session_revoked_by FOREIGN KEY (revoked_by) REFERENCES subject (subject_id)
);
