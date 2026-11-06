-- API 키 폐기 시각·폐기한 사람. 예전에 폐기된 키는 시각을 모른다 (NULL)
ALTER TABLE api_key
    ADD COLUMN revoked_at DATETIME(6) NULL COMMENT '폐기 시각' AFTER revoked,
    ADD COLUMN revoked_by BIGINT      NULL COMMENT '폐기한 subject (사용 중지·퇴사 일괄 폐기 등 모르면 NULL)' AFTER revoked_at,
    ADD CONSTRAINT fk_api_key_revoked_by FOREIGN KEY (revoked_by) REFERENCES subject (subject_id);

-- 접근 요청이 끝난(승인·반려·취소·만료) 시각. 예전에 끝난 요청은 시각을 모른다 (NULL)
ALTER TABLE access_request
    ADD COLUMN closed_at DATETIME(6) NULL COMMENT '처리가 끝난 시각 (승인·반려·취소·만료)' AFTER status;

-- 비상 접근을 시작·요청할 수 있는 그룹. NULL 이면 활성 사용자 누구나 (예전과 같음)
ALTER TABLE break_glass_policy
    ADD COLUMN eligible_group_id BIGINT NULL COMMENT '시작할 수 있는 그룹 (NULL = 모두)' AFTER max_duration_minutes,
    ADD CONSTRAINT fk_break_glass_policy_eligible_group FOREIGN KEY (eligible_group_id) REFERENCES user_group (group_id);
