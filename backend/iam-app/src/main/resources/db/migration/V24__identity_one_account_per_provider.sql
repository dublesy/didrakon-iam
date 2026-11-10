-- 한 사람에게 IdP 마다 계정은 하나다. 로컬 계정이 둘 생기면 관리자 초기화·잠금 해제가 그중 하나에만 적용된다
ALTER TABLE identity ADD UNIQUE KEY uk_identity_subject_provider (subject_id, provider_id);

-- 로그인 ID 비교 규칙(대소문자·악센트 무시)을 DB 서버 기본 설정에 맡기지 않고 고정한다.
-- 서버 기본이 _bin 이면 같은 ID 를 대소문자만 바꿔 다른 계정으로 만들 수 있다
ALTER TABLE identity MODIFY external_id VARCHAR(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci NOT NULL COMMENT 'IdP 쪽 고유 식별자';
