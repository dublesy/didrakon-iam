-- 패스키(WebAuthn). Spring Security 의 JdbcPublicKeyCredentialUserEntityRepository·JdbcUserCredentialRepository 가 쓰는 표준 테이블
-- (spring-security-web 7.1.2 의 user-entities-schema.sql, user-credentials-schema.sql) 대비 변경:
--   * 사용자 핸들·자격 증명 ID 는 base64url 이라 대소문자를 구분해야 한다 → ascii_bin.
--     (utf8mb4 VARCHAR(1000) 은 PK 인덱스 최대 길이 3072바이트도 넘는다. 자격 증명 ID 는 최대 1023바이트 → base64url 1364자)
--   * timestamp → DATETIME(6) (프로젝트 시간 규칙, 2038년 한계 회피)
--   * user_entities.name(= subject ID) UNIQUE, user_credentials 의 사용자 인덱스와 FK
CREATE TABLE user_entities (
    id           VARCHAR(100)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'WebAuthn 사용자 핸들 (base64url)',
    name         VARCHAR(100)  NOT NULL COMMENT 'subject ID. 패스키 로그인의 principal 이름(토큰 sub)이 된다',
    display_name VARCHAR(200)  NULL,
    PRIMARY KEY (id),
    UNIQUE KEY uk_user_entities_name (name)
);

CREATE TABLE user_credentials (
    credential_id                VARCHAR(1400) CHARACTER SET ascii COLLATE ascii_bin NOT NULL COMMENT 'base64url',
    user_entity_user_id          VARCHAR(100)  CHARACTER SET ascii COLLATE ascii_bin NOT NULL,
    public_key                   BLOB          NOT NULL COMMENT 'COSE 공개키',
    signature_count              BIGINT        NULL,
    uv_initialized               BOOLEAN       NULL,
    backup_eligible              BOOLEAN       NOT NULL,
    authenticator_transports     VARCHAR(1000) NULL,
    public_key_credential_type   VARCHAR(100)  NULL,
    backup_state                 BOOLEAN       NOT NULL,
    attestation_object           BLOB          NULL,
    attestation_client_data_json BLOB          NULL,
    created                      DATETIME(6)   NULL,
    last_used                    DATETIME(6)   NULL,
    label                        VARCHAR(1000) NOT NULL COMMENT '사용자가 붙인 이름',
    PRIMARY KEY (credential_id),
    KEY idx_user_credentials_user (user_entity_user_id),
    CONSTRAINT fk_user_credentials_user_entity FOREIGN KEY (user_entity_user_id) REFERENCES user_entities (id)
);
