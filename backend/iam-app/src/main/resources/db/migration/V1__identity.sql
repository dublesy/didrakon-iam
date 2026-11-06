-- identity: Subject(JOINED 상속), IdP, 외부 계정, 조직, 소속, 그룹

CREATE TABLE subject (
    subject_id   BIGINT        NOT NULL AUTO_INCREMENT,
    subject_type VARCHAR(30)   NOT NULL COMMENT 'USER, SERVICE, AI_AGENT, APPLICATION',
    subject_name VARCHAR(200)  NOT NULL,
    status       VARCHAR(30)   NOT NULL COMMENT 'ACTIVE, LOCKED, DISABLED, RETIRED',
    description  VARCHAR(1000) NULL,
    created_at   DATETIME(6)   NOT NULL,
    updated_at   DATETIME(6)   NOT NULL,
    PRIMARY KEY (subject_id),
    KEY idx_subject_type_status (subject_type, status)
);

CREATE TABLE user (
    subject_id        BIGINT       NOT NULL,
    emp_no            VARCHAR(50)  NOT NULL COMMENT '그룹 전체 고유',
    name              VARCHAR(200) NOT NULL,
    email             VARCHAR(255) NULL,
    phone             VARCHAR(30)  NULL,
    employment_status VARCHAR(30)  NOT NULL COMMENT 'EMPLOYED, LEAVE, RETIRED',
    hire_date         DATE         NULL COMMENT '그룹 최초 입사일',
    retire_date       DATE         NULL,
    last_login_at     DATETIME(6)  NULL,
    PRIMARY KEY (subject_id),
    UNIQUE KEY uk_user_emp_no (emp_no),
    CONSTRAINT fk_user_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id)
);

CREATE TABLE service_account (
    subject_id       BIGINT        NOT NULL,
    service_name     VARCHAR(200)  NOT NULL,
    owner_subject_id BIGINT        NOT NULL,
    environment      VARCHAR(30)   NOT NULL COMMENT 'DEV, STG, PROD',
    last_used_at     DATETIME(6)   NULL,
    PRIMARY KEY (subject_id),
    CONSTRAINT fk_service_account_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_service_account_owner FOREIGN KEY (owner_subject_id) REFERENCES subject (subject_id)
);

CREATE TABLE ai_agent (
    subject_id       BIGINT       NOT NULL,
    agent_name       VARCHAR(200) NOT NULL,
    agent_type       VARCHAR(100) NULL,
    owner_subject_id BIGINT       NOT NULL,
    model_name       VARCHAR(200) NULL,
    risk_level       VARCHAR(30)  NOT NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    is_autonomous    BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (subject_id),
    CONSTRAINT fk_ai_agent_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_ai_agent_owner FOREIGN KEY (owner_subject_id) REFERENCES subject (subject_id)
);

CREATE TABLE application (
    subject_id       BIGINT       NOT NULL,
    application_name VARCHAR(200) NOT NULL,
    application_type VARCHAR(30)  NOT NULL COMMENT 'WEB, MOBILE, API, BATCH',
    owner_subject_id BIGINT       NOT NULL,
    environment      VARCHAR(30)  NOT NULL COMMENT 'DEV, STG, PROD',
    PRIMARY KEY (subject_id),
    CONSTRAINT fk_application_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_application_owner FOREIGN KEY (owner_subject_id) REFERENCES subject (subject_id)
);

CREATE TABLE identity_provider (
    provider_id   BIGINT        NOT NULL AUTO_INCREMENT,
    provider_code VARCHAR(100)  NOT NULL,
    provider_name VARCHAR(200)  NOT NULL,
    provider_type VARCHAR(30)   NOT NULL COMMENT 'LOCAL, OIDC, SAML, LDAP, AD',
    issuer        VARCHAR(1000) NULL,
    metadata_url  VARCHAR(1000) NULL,
    is_active     BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (provider_id),
    UNIQUE KEY uk_identity_provider_code (provider_code)
);

CREATE TABLE identity (
    identity_id   BIGINT       NOT NULL AUTO_INCREMENT,
    subject_id    BIGINT       NOT NULL,
    provider_id   BIGINT       NOT NULL,
    external_id   VARCHAR(255) NOT NULL COMMENT 'IdP 쪽 고유 식별자',
    login_id      VARCHAR(255) NULL,
    email         VARCHAR(255) NULL,
    is_primary    BOOLEAN      NOT NULL DEFAULT FALSE,
    is_verified   BOOLEAN      NOT NULL DEFAULT FALSE,
    last_login_at DATETIME(6)  NULL,
    PRIMARY KEY (identity_id),
    UNIQUE KEY uk_identity_provider_external (provider_id, external_id),
    CONSTRAINT fk_identity_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_identity_provider FOREIGN KEY (provider_id) REFERENCES identity_provider (provider_id)
);

CREATE TABLE organization (
    org_id         BIGINT       NOT NULL AUTO_INCREMENT,
    parent_org_id  BIGINT       NULL,
    company_org_id BIGINT       NULL COMMENT '소속 법인 (비정규화). GROUP 등 법인 위 조직은 NULL',
    org_code       VARCHAR(100) NOT NULL,
    org_name       VARCHAR(200) NOT NULL,
    org_type       VARCHAR(30)  NOT NULL COMMENT 'GROUP, COMPANY, DIVISION, DEPARTMENT, TEAM, CENTER',
    org_level      INT          NOT NULL COMMENT '최상위 = 1',
    is_active      BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at     DATETIME(6)  NOT NULL,
    updated_at     DATETIME(6)  NOT NULL,
    PRIMARY KEY (org_id),
    UNIQUE KEY uk_organization_code (org_code),
    CONSTRAINT fk_organization_parent FOREIGN KEY (parent_org_id) REFERENCES organization (org_id),
    CONSTRAINT fk_organization_company FOREIGN KEY (company_org_id) REFERENCES organization (org_id)
);

CREATE TABLE subject_organization (
    membership_id   BIGINT       NOT NULL AUTO_INCREMENT,
    subject_id      BIGINT       NOT NULL,
    org_id          BIGINT       NOT NULL,
    membership_type VARCHAR(30)  NOT NULL COMMENT 'PRIMARY, SECONDARY, TEMPORARY',
    job_title       VARCHAR(100) NULL COMMENT '소속별 직위',
    job_grade       VARCHAR(100) NULL COMMENT '소속별 직급',
    is_manager      BOOLEAN      NOT NULL DEFAULT FALSE,
    valid_from      DATETIME(6)  NOT NULL,
    valid_until     DATETIME(6)  NULL COMMENT 'NULL = 현재 소속',
    -- 활성 PRIMARY 소속만 subject_id 값을 가지므로 UNIQUE 로 subject당 1개를 보장한다
    active_primary_subject_id BIGINT
        GENERATED ALWAYS AS (IF(membership_type = 'PRIMARY' AND valid_until IS NULL, subject_id, NULL)) VIRTUAL,
    PRIMARY KEY (membership_id),
    UNIQUE KEY uk_subject_organization_active_primary (active_primary_subject_id),
    KEY idx_subject_organization_subject (subject_id, valid_until),
    KEY idx_subject_organization_org (org_id, valid_until),
    CONSTRAINT fk_subject_organization_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_subject_organization_org FOREIGN KEY (org_id) REFERENCES organization (org_id)
);

CREATE TABLE user_group (
    group_id        BIGINT       NOT NULL AUTO_INCREMENT,
    group_code      VARCHAR(100) NOT NULL,
    group_name      VARCHAR(200) NOT NULL,
    group_type      VARCHAR(30)  NOT NULL COMMENT 'STATIC, DYNAMIC',
    rule_expression JSON         NULL COMMENT 'DYNAMIC 그룹의 구성원 규칙',
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at      DATETIME(6)  NOT NULL,
    updated_at      DATETIME(6)  NOT NULL,
    PRIMARY KEY (group_id),
    UNIQUE KEY uk_user_group_code (group_code)
);

CREATE TABLE group_member (
    group_id    BIGINT      NOT NULL,
    subject_id  BIGINT      NOT NULL,
    source_type VARCHAR(30) NOT NULL COMMENT 'MANUAL, RULE, SYNC',
    valid_from  DATETIME(6) NOT NULL,
    valid_until DATETIME(6) NULL,
    PRIMARY KEY (group_id, subject_id),
    KEY idx_group_member_subject (subject_id),
    CONSTRAINT fk_group_member_group FOREIGN KEY (group_id) REFERENCES user_group (group_id),
    CONSTRAINT fk_group_member_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id)
);
