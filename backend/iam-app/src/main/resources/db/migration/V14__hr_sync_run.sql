-- HR 연동(POST /api/v1/hr/sync) 실행 기록. 미리보기(dry_run)도 남긴다. 변경 자체는 각 변경의 감사 기록(AUDIT_EVENT)에 남는다
CREATE TABLE hr_sync_run (
    run_id           BIGINT      NOT NULL AUTO_INCREMENT,
    dry_run          BOOLEAN     NOT NULL DEFAULT FALSE COMMENT 'TRUE 면 미리보기 (레코드마다 롤백)',
    started_at       DATETIME(6) NOT NULL,
    finished_at      DATETIME(6) NOT NULL,
    actor_subject_id BIGINT      NULL COMMENT '실행한 사용자·서비스 계정. client credentials 토큰이면 NULL (기록용, FK 없음)',
    total            INT         NOT NULL COMMENT '받은 레코드 수',
    summary          JSON        NOT NULL COMMENT '처리 결과별 레코드 수 {"CREATED": 3, ...}',
    errors           JSON        NOT NULL COMMENT '오류 레코드 앞 100건 [{"empNo", "message"}]',
    missing_count    INT         NULL COMMENT 'reportMissing 일 때 피드에 없는 사용 중 사용자 수. 요청하지 않았으면 NULL',
    PRIMARY KEY (run_id),
    KEY idx_hr_sync_run_started_at (started_at)
);
