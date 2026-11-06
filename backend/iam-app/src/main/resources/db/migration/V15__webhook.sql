-- 외부 webhook: IAM 변경 이벤트를 연동 시스템에 보낸다 (아웃박스).
-- 업무 변경과 같은 트랜잭션에서 webhook_delivery 행을 쓰고, 스케줄러가 커밋된 행만 꺼내 보낸다. 업무 변경이 롤백되면 전달도 없다
CREATE TABLE webhook_subscription (
    subscription_id  BIGINT       NOT NULL AUTO_INCREMENT,
    name             VARCHAR(200) NOT NULL,
    url              VARCHAR(500) NOT NULL COMMENT '받는 주소 (http(s) 절대 주소)',
    secret_reference VARCHAR(100) NOT NULL COMMENT '서명 비밀값의 SecretStore 참조 (secret_value). 원문은 만들 때·교체할 때 한 번만 보여준다',
    event_types      JSON         NOT NULL COMMENT '받을 이벤트 유형 배열. ["*"] 이면 전체',
    is_active        BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at       DATETIME(6)  NOT NULL,
    created_by       BIGINT       NULL COMMENT '만든 사용자 (기록용, FK 없음)',
    PRIMARY KEY (subscription_id)
);

CREATE TABLE webhook_delivery (
    delivery_id      BIGINT       NOT NULL AUTO_INCREMENT,
    subscription_id  BIGINT       NOT NULL,
    event_id         CHAR(36)     NOT NULL COMMENT '이벤트 UUID. 한 이벤트를 여러 구독에 보내면 같은 값',
    event_type       VARCHAR(50)  NOT NULL,
    payload          JSON         NOT NULL COMMENT '보내는 본문 그대로',
    status           VARCHAR(20)  NOT NULL COMMENT 'PENDING, SUCCEEDED, FAILED(재시도 대기), DEAD(포기)',
    attempts         INT          NOT NULL DEFAULT 0,
    next_attempt_at  DATETIME(6)  NOT NULL,
    last_status_code INT          NULL,
    last_error       VARCHAR(200) NULL COMMENT '마지막 실패 사유 요약 (응답 본문은 남기지 않는다)',
    created_at       DATETIME(6)  NOT NULL,
    delivered_at     DATETIME(6)  NULL,
    PRIMARY KEY (delivery_id),
    KEY idx_webhook_delivery_due (status, next_attempt_at),
    KEY idx_webhook_delivery_subscription (subscription_id, delivery_id),
    CONSTRAINT fk_webhook_delivery_subscription FOREIGN KEY (subscription_id) REFERENCES webhook_subscription (subscription_id),
    CONSTRAINT ck_webhook_delivery_status CHECK (status IN ('PENDING', 'SUCCEEDED', 'FAILED', 'DEAD'))
);
