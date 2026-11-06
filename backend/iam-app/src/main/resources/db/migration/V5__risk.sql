-- risk: 위험 정책, 위험 신호, 위험 평가

CREATE TABLE risk_policy (
    risk_policy_id       BIGINT       NOT NULL AUTO_INCREMENT,
    policy_name          VARCHAR(200) NOT NULL,
    risk_type            VARCHAR(30)  NOT NULL COMMENT 'LOGIN, DATA_ACCESS, PRIVILEGE, JIT',
    condition_expression JSON         NOT NULL,
    risk_score           INT          NOT NULL,
    action               VARCHAR(30)  NOT NULL COMMENT 'ALLOW, DENY, CHALLENGE, APPROVAL',
    is_active            BOOLEAN      NOT NULL DEFAULT TRUE,
    PRIMARY KEY (risk_policy_id)
);

CREATE TABLE risk_signal (
    risk_signal_id BIGINT      NOT NULL AUTO_INCREMENT,
    subject_id     BIGINT      NOT NULL,
    signal_type    VARCHAR(30) NOT NULL COMMENT 'NEW_DEVICE, FOREIGN_IP, UNUSUAL_TIME, MASS_ACCESS',
    risk_score     INT         NOT NULL,
    details        JSON        NULL,
    detected_at    DATETIME(6) NOT NULL,
    PRIMARY KEY (risk_signal_id),
    KEY idx_risk_signal_subject (subject_id, detected_at),
    CONSTRAINT fk_risk_signal_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id)
);

CREATE TABLE risk_assessment (
    assessment_id BIGINT      NOT NULL AUTO_INCREMENT,
    subject_id    BIGINT      NOT NULL,
    request_id    BIGINT      NULL COMMENT '접근 요청 평가일 때만',
    risk_score    INT         NOT NULL,
    risk_level    VARCHAR(30) NOT NULL COMMENT 'LOW, MEDIUM, HIGH, CRITICAL',
    decision      VARCHAR(30) NOT NULL COMMENT 'ALLOW, DENY, CHALLENGE, APPROVAL',
    assessed_at   DATETIME(6) NOT NULL,
    PRIMARY KEY (assessment_id),
    KEY idx_risk_assessment_subject (subject_id, assessed_at),
    CONSTRAINT fk_risk_assessment_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_risk_assessment_request FOREIGN KEY (request_id) REFERENCES access_request (request_id)
);
