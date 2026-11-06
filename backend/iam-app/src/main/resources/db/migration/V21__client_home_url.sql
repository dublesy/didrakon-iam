-- 앱 런처: IAM 홈(로그인 서버의 내 계정 화면)에 연동 시스템 바로가기를 보여 주기 위한 시작 주소.
-- 비어 있으면 앱 목록에 나오지 않는다 (서버 간 호출 클라이언트, 관리 콘솔 등)
ALTER TABLE sso_client
    ADD COLUMN home_url VARCHAR(500) NULL COMMENT '앱 런처 시작 주소 (사용자가 눌러 들어가는 주소)' AFTER supabase_role_claim;
