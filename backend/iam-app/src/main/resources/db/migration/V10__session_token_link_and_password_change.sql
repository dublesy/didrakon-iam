-- P0 보완: 로그인 세션과 OAuth2 인가 기록 연결, 다음 로그인 시 비밀번호 변경 강제

-- 어느 로그인 세션에서 나온 인가(토큰 묶음)인지. 세션을 끊으면 이 인가의 refresh token 도 함께 지운다.
-- oauth2_authorization 은 SAS 가 관리하는 테이블이라 FK 를 걸지 않는다
CREATE TABLE login_session_authorization (
    authorization_id VARCHAR(100) NOT NULL COMMENT 'oauth2_authorization.id',
    session_id       BIGINT       NOT NULL,
    subject_id       BIGINT       NOT NULL,
    created_at       DATETIME(6)  NOT NULL,
    PRIMARY KEY (authorization_id),
    KEY idx_login_session_authorization_session (session_id),
    KEY idx_login_session_authorization_subject (subject_id),
    CONSTRAINT fk_login_session_authorization_session FOREIGN KEY (session_id) REFERENCES login_session (session_id)
);

ALTER TABLE local_credential
    ADD COLUMN must_change_password BOOLEAN NOT NULL DEFAULT FALSE COMMENT '관리자 초기화 뒤 다음 로그인에서 바꿔야 함' AFTER password_expire_at;
