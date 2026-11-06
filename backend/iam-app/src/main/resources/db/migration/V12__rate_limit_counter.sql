-- 여러 서버가 함께 세는 호출 수 제한 카운터 (iam.rate-limit.store=jdbc 일 때 로그인·토큰 경로만)
CREATE TABLE rate_limit_counter (
    counter_key  VARCHAR(200) NOT NULL COMMENT '규칙:IP',
    window_start BIGINT       NOT NULL COMMENT '구간 시작 (epoch 초)',
    hit_count    INT          NOT NULL,
    PRIMARY KEY (counter_key, window_start),
    KEY idx_rate_limit_counter_window (window_start)
);
