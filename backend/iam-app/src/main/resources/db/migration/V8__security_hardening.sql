-- 보안 보완: TOTP 재사용 방지, 스케줄러 분산 락

-- 마지막으로 통과한 TOTP 시간 구간(30초 단위 카운터). 이 값 이하의 코드는 다시 받지 않는다
ALTER TABLE mfa_method
    ADD COLUMN last_used_step BIGINT NULL COMMENT '마지막으로 사용한 TOTP 시간 구간 (재사용 방지)' AFTER is_verified;

-- ShedLock: 여러 인스턴스 중 한 곳에서만 스케줄 작업이 돌도록 잡는 락. 시각은 DB 시각을 쓴다
CREATE TABLE shedlock (
    name       VARCHAR(64)  NOT NULL,
    lock_until DATETIME(3)  NOT NULL,
    locked_at  DATETIME(3)  NOT NULL,
    locked_by  VARCHAR(255) NOT NULL,
    PRIMARY KEY (name)
);
