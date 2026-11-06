-- authn: 자체 비밀번호 로그인용 LOCAL IdP, MFA 비밀값 보관 테이블

INSERT INTO identity_provider (provider_code, provider_name, provider_type, is_active, created_at)
VALUES ('LOCAL', '자체 비밀번호', 'LOCAL', TRUE, NOW(6));

-- SecretStore 의 DB 구현. 비밀값은 앱 키(iam.authn.secret-key)로 AES-GCM 암호화해 저장하고,
-- 업무 테이블(mfa_method.secret_reference 등)에는 secret_ref 만 둔다. 외부 보관소(Vault 등)로 바꾸면 이 테이블은 쓰지 않는다
CREATE TABLE secret_value (
    secret_ref  VARCHAR(64)    NOT NULL COMMENT '무작위 참조 키',
    ciphertext  VARBINARY(1024) NOT NULL COMMENT 'IV(12바이트) + 암호문 + 태그',
    created_at  DATETIME(6)    NOT NULL,
    PRIMARY KEY (secret_ref)
);
