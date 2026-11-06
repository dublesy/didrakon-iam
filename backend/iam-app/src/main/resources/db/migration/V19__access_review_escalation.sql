-- 접근 재검토 기한 경과 시 상위 조직 관리자 이관.
-- escalation_days 가 있으면 기한(due_at)이 지났을 때 바로 닫지 않고, 미결정 항목을 대상자 주 소속 조직의 상위 조직 관리자에게 넘긴 뒤
-- 그 날수만큼 더 기다렸다가(due_at + escalation_days) on_overdue 를 적용하고 닫는다. 비어 있으면 예전처럼 기한에 바로 닫는다.
ALTER TABLE access_review_campaign
    ADD COLUMN escalation_days INT NULL COMMENT '기한 경과 시 상위 관리자에게 넘기고 더 기다리는 날수 (1~30). NULL 이면 이관 없이 기한에 닫는다' AFTER on_overdue,
    ADD COLUMN escalated_at DATETIME(6) NULL COMMENT '상위 관리자 이관을 처리한 시각' AFTER escalation_days,
    ADD CONSTRAINT ck_access_review_campaign_escalation CHECK (escalation_days IS NULL OR escalation_days BETWEEN 1 AND 30);

ALTER TABLE access_review_item
    ADD COLUMN escalated_from_id BIGINT NULL COMMENT '이관 전 검토자. NULL 이고 escalated_at 이 있으면 원래 관리자 몫이던 항목' AFTER reviewer_name,
    ADD COLUMN escalated_from_name VARCHAR(200) NULL COMMENT '이관 전 검토자 이름 (증적)' AFTER escalated_from_id,
    ADD COLUMN escalated_at DATETIME(6) NULL COMMENT '상위 관리자에게 넘긴 시각' AFTER escalated_from_name;
