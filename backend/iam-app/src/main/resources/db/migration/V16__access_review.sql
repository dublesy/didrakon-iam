-- 접근 재검토(Access Review) 캠페인: 주기적으로 역할 할당을 담당자가 "유지·회수"로 확인하고 그 결과를 증적으로 남긴다.
-- 캠페인을 만들 때 대상 할당을 항목(access_review_item)으로 스냅샷한다. 이름·역할·범위 등은 그 시점 값을 함께 저장해,
-- 나중에 기준 데이터가 바뀌어도 "무엇을 누가 언제 어떻게 검토했는지" 그대로 보여줄 수 있게 한다.
-- 조직·그룹 규칙으로 생긴 할당(ORGANIZATION·GROUP)은 개별 회수가 아니라 규칙을 바꿔 검토하므로 대상 출처에 넣을 수 없다.
CREATE TABLE access_review_campaign (
    campaign_id         BIGINT       NOT NULL AUTO_INCREMENT,
    name                VARCHAR(200) NOT NULL,
    scope_type          VARCHAR(20)  NOT NULL COMMENT 'ALL, ORGANIZATION(주 소속 조직 기준), ROLE',
    scope_org_id        BIGINT       NULL COMMENT 'scope_type = ORGANIZATION 일 때',
    scope_role_id       BIGINT       NULL COMMENT 'scope_type = ROLE 일 때',
    include_descendants BOOLEAN      NOT NULL DEFAULT TRUE COMMENT 'ORGANIZATION 이면 하위 조직 구성원까지',
    privileged_only     BOOLEAN      NOT NULL DEFAULT FALSE COMMENT '특권 역할(is_privileged) 할당만',
    sources             JSON         NOT NULL COMMENT '대상 할당 출처 배열 (DIRECT, JIT, DELEGATION, BREAK_GLASS 중)',
    due_at              DATETIME(6)  NOT NULL COMMENT '검토 기한. 지나면 만료 스케줄러가 미결정 항목에 on_overdue 를 적용하고 닫는다',
    on_overdue          VARCHAR(20)  NOT NULL COMMENT 'KEEP, REVOKE',
    status              VARCHAR(20)  NOT NULL COMMENT 'OPEN, CLOSED',
    created_by          BIGINT       NULL COMMENT '만든 사용자 (기록용, FK 없음)',
    created_at          DATETIME(6)  NOT NULL,
    closed_at           DATETIME(6)  NULL,
    PRIMARY KEY (campaign_id),
    KEY idx_access_review_campaign_status_due (status, due_at),
    CONSTRAINT ck_access_review_campaign_scope CHECK (
        (scope_type = 'ALL' AND scope_org_id IS NULL AND scope_role_id IS NULL)
        OR (scope_type = 'ORGANIZATION' AND scope_org_id IS NOT NULL AND scope_role_id IS NULL)
        OR (scope_type = 'ROLE' AND scope_role_id IS NOT NULL AND scope_org_id IS NULL)
    ),
    CONSTRAINT ck_access_review_campaign_on_overdue CHECK (on_overdue IN ('KEEP', 'REVOKE')),
    CONSTRAINT ck_access_review_campaign_status CHECK (status IN ('OPEN', 'CLOSED')),
    CONSTRAINT fk_access_review_campaign_org FOREIGN KEY (scope_org_id) REFERENCES organization (org_id),
    CONSTRAINT fk_access_review_campaign_role FOREIGN KEY (scope_role_id) REFERENCES role (role_id)
);

CREATE TABLE access_review_item (
    item_id                BIGINT        NOT NULL AUTO_INCREMENT,
    campaign_id            BIGINT        NOT NULL,
    assignment_id          BIGINT        NOT NULL,
    subject_id             BIGINT        NOT NULL,
    role_id                BIGINT        NOT NULL,
    scope_id               BIGINT        NOT NULL,
    source_type            VARCHAR(30)   NOT NULL,
    reviewer_id            BIGINT        NULL COMMENT '검토자 = 대상자 주 소속 조직의 관리자(is_manager). 없으면 NULL (관리자가 검토)',
    decision               VARCHAR(20)   NOT NULL COMMENT 'PENDING, KEEP, REVOKE',
    decided_by             BIGINT        NULL COMMENT '결정한 사람. 기한 경과·마감으로 자동 처리되면 NULL',
    decided_at             DATETIME(6)   NULL,
    comment                VARCHAR(1000) NULL,
    -- 증적용 스냅샷 (캠페인 생성 시점 값)
    subject_name           VARCHAR(200)  NOT NULL,
    emp_no                 VARCHAR(50)   NULL,
    org_name               VARCHAR(200)  NULL COMMENT '대상자 주 소속 조직 이름',
    role_code              VARCHAR(100)  NOT NULL,
    role_name              VARCHAR(200)  NOT NULL,
    is_privileged          BOOLEAN       NOT NULL,
    scope_name             VARCHAR(200)  NOT NULL,
    reviewer_name          VARCHAR(200)  NULL,
    assignment_valid_from  DATETIME(6)   NOT NULL,
    assignment_valid_until DATETIME(6)   NULL,
    review_required        BOOLEAN       NOT NULL COMMENT '생성 시점에 할당이 재검토 표시(전적 등)였는지',
    PRIMARY KEY (item_id),
    UNIQUE KEY uk_access_review_item_assignment (campaign_id, assignment_id),
    KEY idx_access_review_item_campaign_decision (campaign_id, decision),
    KEY idx_access_review_item_reviewer_decision (reviewer_id, decision),
    CONSTRAINT ck_access_review_item_decision CHECK (decision IN ('PENDING', 'KEEP', 'REVOKE')),
    CONSTRAINT fk_access_review_item_campaign FOREIGN KEY (campaign_id) REFERENCES access_review_campaign (campaign_id),
    CONSTRAINT fk_access_review_item_assignment FOREIGN KEY (assignment_id) REFERENCES role_assignment (assignment_id),
    CONSTRAINT fk_access_review_item_subject FOREIGN KEY (subject_id) REFERENCES subject (subject_id),
    CONSTRAINT fk_access_review_item_reviewer FOREIGN KEY (reviewer_id) REFERENCES subject (subject_id)
);
