-- OIDC Back-Channel Logout: 로그인 세션이 끝나면 이 주소로 로그아웃 토큰을 보낸다 (비우면 보내지 않음)
ALTER TABLE sso_client
    ADD COLUMN backchannel_logout_uri VARCHAR(500) NULL COMMENT 'OIDC Back-Channel Logout 수신 주소' AFTER require_mfa;
