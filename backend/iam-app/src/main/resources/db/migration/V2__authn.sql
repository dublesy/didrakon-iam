-- authn: Spring Authorization Server 표준 테이블, SSO 클라이언트, 로컬 비밀번호, 세션, MFA, 인증 이벤트, 자격 증명
-- SAS 표준 스키마(spring-security-oauth2-authorization-server 7.1.2) 대비 변경:
--   * timestamp → DATETIME(6) (프로젝트 시간 규칙, 2038년 한계 회피)
--   * oauth2_authorization 의 code·token 값은 SHA-256 hex(64) 로 저장하고 인덱스 (ERD 결정 사항 3)

CREATE TABLE oauth2_registered_client (
    id                            VARCHAR(100)  NOT NULL,
    client_id                     VARCHAR(100)  NOT NULL,
    client_id_issued_at           DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    client_secret                 VARCHAR(200)  NULL COMMENT 'PasswordEncoder 로 인코딩',
    client_secret_expires_at      DATETIME(6)   NULL,
    client_name                   VARCHAR(200)  NOT NULL,
    client_authentication_methods VARCHAR(1000) NOT NULL,
    authorization_grant_types     VARCHAR(1000) NOT NULL,
    redirect_uris                 VARCHAR(1000) NULL,
    post_logout_redirect_uris     VARCHAR(1000) NULL,
    scopes                        VARCHAR(1000) NOT NULL,
    client_settings               VARCHAR(2000) NOT NULL,
    token_settings                VARCHAR(2000) NOT NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_oauth2_registered_client_client_id (client_id)
);

CREATE TABLE oauth2_authorization (
    id                            VARCHAR(100)  NOT NULL,
    registered_client_id          VARCHAR(100)  NOT NULL,
    principal_name                VARCHAR(200)  NOT NULL,
    authorization_grant_type      VARCHAR(100)  NOT NULL,
    authorized_scopes             VARCHAR(1000) NULL,
    attributes                    BLOB          NULL,
    state                         VARCHAR(500)  NULL,
    authorization_code_value      VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    authorization_code_issued_at  DATETIME(6)   NULL,
    authorization_code_expires_at DATETIME(6)   NULL,
    authorization_code_metadata   BLOB          NULL,
    access_token_value            VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    access_token_issued_at        DATETIME(6)   NULL,
    access_token_expires_at       DATETIME(6)   NULL,
    access_token_metadata         BLOB          NULL,
    access_token_type             VARCHAR(100)  NULL,
    access_token_scopes           VARCHAR(1000) NULL,
    oidc_id_token_value           VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    oidc_id_token_issued_at       DATETIME(6)   NULL,
    oidc_id_token_expires_at      DATETIME(6)   NULL,
    oidc_id_token_metadata        BLOB          NULL,
    refresh_token_value           VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    refresh_token_issued_at       DATETIME(6)   NULL,
    refresh_token_expires_at      DATETIME(6)   NULL,
    refresh_token_metadata        BLOB          NULL,
    user_code_value               VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    user_code_issued_at           DATETIME(6)   NULL,
    user_code_expires_at          DATETIME(6)   NULL,
    user_code_metadata            BLOB          NULL,
    device_code_value             VARCHAR(64)   NULL COMMENT 'SHA-256 hex',
    device_code_issued_at         DATETIME(6)   NULL,
    device_code_expires_at        DATETIME(6)   NULL,
    device_code_metadata          BLOB          NULL,
    PRIMARY KEY (id),
    KEY idx_oauth2_authorization_state (state),
    KEY idx_oauth2_authorization_code (authorization_code_value),
    KEY idx_oauth2_authorization_access_token (access_token_value),
    KEY idx_oauth2_authorization_id_token (oidc_id_token_value),
    KEY idx_oauth2_authorization_refresh_token (refresh_token_value),
    KEY idx_oauth2_authorization_user_code (user_code_value),
    KEY idx_oauth2_authorization_device_code (device_code_value),
    CONSTRAINT fk_oauth2_authorization_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client (id)
);

CREATE TABLE oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          VARCHAR(1000) NOT NULL,
    PRIMARY KEY (registered_client_id, principal_name),
    CONSTRAINT fk_oauth2_consent_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client (id)
);

CREATE TABLE sso_client (
    client_id            BIGINT       NOT NULL AUTO_INCREMENT,
    registered_client_id VARCHAR(100) NOT NULL,
    client_code          VARCHAR(100) NOT NULL,
    client_name          VARCHAR(200) NOT NULL,
    client_type          VARCHAR(30)  NOT NULL COMMENT 'WEB, API, MOBILE, BATCH',
    protocol             VARCHAR(30)  NOT NULL COMMENT 'OIDC, SAML',
    require_mfa          BOOLEAN      NOT NULL DEFAULT FALSE,
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at           DATETIME(6)  NOT NULL,
    PRIMARY KEY (client_id),
    UNIQUE KEY uk_sso_client_code (client_code),
    UNIQUE KEY uk_sso_client_registered_client (registered_client_id),
    CONSTRAINT fk_sso_client_registered_client FOREIGN KEY (registered_client_id) REFERENCES oauth2_registered_client (id)
);

CREATE TABLE local_credential (
    identity_id          BIGINT       NOT NULL,
    password_hash        VARCHAR(255) NOT NULL COMMENT 'PasswordEncoder 결과 ({id} 접두어 포함)',
    password_changed_at  DATETIME(6)  NOT NULL,
    password_expire_at   DATETIME(6)  NULL,
    failed_attempt_count INT          NOT NULL DEFAULT 0,
    locked_until         DATETIME(6)  NULL,
    PRIMARY KEY (identity_id),
    CONSTRAINT fk_local_credential_identity FOREIGN KEY (identity_id) REFERENCES identity (identity_id)
);

CREATE TABLE login_session (
    session_id           BIGINT       NOT NULL AUTO_INCREMENT,
    session_key_hash     VARCHAR(64)  NOT NULL COMMENT '외부 노출 세션 키의 SHA-256 hex',
    subject_id           BIGINT       NOT NULL,
    identity_id          BIGINT       NOT NULL,
    device_id            VARCHAR(200) NULL,
    ip_address           VARCHAR(45)  NULL,
    user_agent           VARCHAR(500) NULL,
    authentication_level VARCHAR(30)  NOT NULL COMMENT 'PASSWORD, MFA, CERTIFICATE',
    login_at             DATETIME(6)  NOT NULL,
    expire_at            DATETIME(6)  NOT NULL,
    last_activity_at     DATETIME(6)  NOT NULL,
    status               VARCHAR(30)  NOT NULL COMMENT 'ACTIVE, EXPIRED, REVOKED',
    PRIMARY KEY (session_id),
    UNIQUE KEY uk_login_session_key_hash (session_key_hash),
    KEY idx_login_session_subject_status (subject_id, status),
    CONSTRAINT fk_login_session_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_login_session_identity FOREIGN KEY (identity_id) REFERENCES identity (identity_id)
);

CREATE TABLE mfa_method (
    mfa_method_id    BIGINT       NOT NULL AUTO_INCREMENT,
    subject_id       BIGINT       NOT NULL,
    method_type      VARCHAR(30)  NOT NULL COMMENT 'TOTP, SMS, EMAIL, FIDO2, PASSKEY',
    secret_reference VARCHAR(500) NULL COMMENT '비밀값 자체가 아닌 보관소 참조',
    is_primary       BOOLEAN      NOT NULL DEFAULT FALSE,
    is_verified      BOOLEAN      NOT NULL DEFAULT FALSE,
    registered_at    DATETIME(6)  NOT NULL,
    PRIMARY KEY (mfa_method_id),
    KEY idx_mfa_method_subject (subject_id),
    CONSTRAINT fk_mfa_method_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id)
);

-- 대량 적재 테이블: 물리 FK 없음. 월 단위 RANGE 파티셔닝이 가능하도록 PK 에 created_at 을 포함한다
CREATE TABLE authentication_event (
    authentication_event_id BIGINT        NOT NULL AUTO_INCREMENT,
    subject_id              BIGINT        NULL,
    identity_id             BIGINT        NULL,
    event_type              VARCHAR(30)   NOT NULL COMMENT 'LOGIN, LOGOUT, MFA, PASSWORD_CHANGE, FAILED_LOGIN',
    result                  VARCHAR(30)   NOT NULL COMMENT 'SUCCESS, FAILURE, CHALLENGE',
    ip_address              VARCHAR(45)   NULL,
    device_id               VARCHAR(200)  NULL,
    user_agent              VARCHAR(500)  NULL,
    failure_reason          VARCHAR(1000) NULL,
    created_at              DATETIME(6)   NOT NULL,
    PRIMARY KEY (authentication_event_id, created_at),
    KEY idx_authentication_event_subject (subject_id, created_at)
);

CREATE TABLE api_key (
    api_key_id       BIGINT       NOT NULL AUTO_INCREMENT,
    subject_id       BIGINT       NOT NULL,
    client_id        BIGINT       NULL,
    key_hash         VARCHAR(64)  NOT NULL COMMENT 'SHA-256 hex',
    key_name         VARCHAR(200) NOT NULL,
    scope_expression JSON         NULL,
    issued_at        DATETIME(6)  NOT NULL,
    expire_at        DATETIME(6)  NULL,
    last_used_at     DATETIME(6)  NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (api_key_id),
    UNIQUE KEY uk_api_key_hash (key_hash),
    CONSTRAINT fk_api_key_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_api_key_client FOREIGN KEY (client_id) REFERENCES sso_client (client_id)
);

CREATE TABLE service_credential (
    credential_id    BIGINT       NOT NULL AUTO_INCREMENT,
    subject_id       BIGINT       NOT NULL,
    credential_type  VARCHAR(30)  NOT NULL COMMENT 'CLIENT_SECRET, CERTIFICATE, PRIVATE_KEY',
    secret_reference VARCHAR(500) NOT NULL COMMENT '비밀값 자체가 아닌 보관소 참조',
    issued_at        DATETIME(6)  NOT NULL,
    expire_at        DATETIME(6)  NULL,
    revoked          BOOLEAN      NOT NULL DEFAULT FALSE,
    PRIMARY KEY (credential_id),
    KEY idx_service_credential_subject (subject_id),
    CONSTRAINT fk_service_credential_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id)
);
