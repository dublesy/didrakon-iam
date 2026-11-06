-- Supabase Third-Party Auth(Custom OIDC) 호환. Supabase 는 외부 IdP 의 JWT 에 role = "authenticated" 가 있어야
-- 로그인한 사용자로 본다. 이 값을 켠 클라이언트에 발급하는 접근·ID 토큰에만 그 claim 을 넣는다
ALTER TABLE sso_client
    ADD COLUMN supabase_role_claim BOOLEAN NOT NULL DEFAULT FALSE COMMENT '토큰에 role = authenticated 를 넣는다 (Supabase RLS 용)' AFTER backchannel_logout_uri;
