-- audit: 감사 이벤트, 정책·역할 변경 이력

-- 대량 적재 테이블: 물리 FK 없음. 월 단위 RANGE 파티셔닝이 가능하도록 PK 에 created_at 을 포함한다
CREATE TABLE audit_event (
    event_id          BIGINT        NOT NULL AUTO_INCREMENT,
    actor_subject_id  BIGINT        NULL COMMENT '시스템 작업은 NULL',
    target_subject_id BIGINT        NULL,
    event_type        VARCHAR(30)   NOT NULL COMMENT 'LOGIN, LOGOUT, ROLE_CHANGE, PERMISSION_CHANGE, MEMBERSHIP_CHANGE, JIT, POLICY_CHANGE, DATA_ACCESS',
    resource_type     VARCHAR(100)  NULL,
    resource_id       VARCHAR(200)  NULL,
    action            VARCHAR(30)   NULL,
    before_value      JSON          NULL,
    after_value       JSON          NULL,
    reason            VARCHAR(1000) NULL,
    trace_id          VARCHAR(64)   NULL,
    ip_address        VARCHAR(45)   NULL,
    device_id         VARCHAR(200)  NULL,
    user_agent        VARCHAR(500)  NULL,
    created_at        DATETIME(6)   NOT NULL,
    PRIMARY KEY (event_id, created_at),
    KEY idx_audit_event_actor (actor_subject_id, created_at),
    KEY idx_audit_event_target (target_subject_id, created_at),
    KEY idx_audit_event_type (event_type, created_at),
    KEY idx_audit_event_trace (trace_id)
);

CREATE TABLE policy_change_history (
    history_id    BIGINT        NOT NULL AUTO_INCREMENT,
    policy_id     BIGINT        NOT NULL,
    old_version   INT           NULL COMMENT '최초 생성은 NULL',
    new_version   INT           NULL,
    changed_by    BIGINT        NULL,
    change_reason VARCHAR(1000) NULL,
    old_value     JSON          NULL,
    new_value     JSON          NULL,
    changed_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (history_id),
    KEY idx_policy_change_history_policy (policy_id, changed_at),
    CONSTRAINT fk_policy_change_history_policy FOREIGN KEY (policy_id) REFERENCES policy (policy_id),
    CONSTRAINT fk_policy_change_history_changed_by FOREIGN KEY (changed_by) REFERENCES subject (subject_id)
);

CREATE TABLE role_change_history (
    history_id    BIGINT        NOT NULL AUTO_INCREMENT,
    role_id       BIGINT        NOT NULL,
    subject_id    BIGINT        NOT NULL,
    change_type   VARCHAR(30)   NOT NULL COMMENT 'ASSIGN, REVOKE, MODIFY, REVIEW, EXPIRE',
    assignment_id BIGINT        NULL,
    changed_by    BIGINT        NULL COMMENT '시스템 작업은 NULL',
    reason        VARCHAR(1000) NULL,
    changed_at    DATETIME(6)   NOT NULL,
    PRIMARY KEY (history_id),
    KEY idx_role_change_history_subject (subject_id, changed_at),
    CONSTRAINT fk_role_change_history_role FOREIGN KEY (role_id) REFERENCES role (role_id),
    CONSTRAINT fk_role_change_history_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_role_change_history_assignment FOREIGN KEY (assignment_id) REFERENCES role_assignment (assignment_id),
    CONSTRAINT fk_role_change_history_changed_by FOREIGN KEY (changed_by) REFERENCES subject (subject_id)
);
