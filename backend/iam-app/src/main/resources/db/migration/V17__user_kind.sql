-- 사용자 구분: 임직원(EMPLOYEE)과 외부 사용자(EXTERNAL, 예: B2B 고객사 사용자).
-- 외부 사용자는 사번이 없고 이메일로 식별한다. 사번 UNIQUE 는 그대로 두며, MySQL 은 NULL 을 여러 개 허용한다.
-- 외부 사용자 이메일은 외부 사용자끼리만 고유하다 (임직원 이메일과는 겹쳐도 된다):
-- generated column 은 EXTERNAL 일 때만 email 을 갖고, UNIQUE 는 NULL 을 서로 다른 값으로 본다.
ALTER TABLE user
    ADD COLUMN user_kind VARCHAR(30) NOT NULL DEFAULT 'EMPLOYEE' COMMENT 'EMPLOYEE, EXTERNAL' AFTER subject_id,
    MODIFY COLUMN emp_no VARCHAR(50) NULL COMMENT '그룹 전체 고유. EXTERNAL 은 NULL',
    ADD COLUMN external_email VARCHAR(255)
        GENERATED ALWAYS AS (IF(user_kind = 'EXTERNAL', email, NULL)) VIRTUAL,
    ADD UNIQUE KEY uk_user_external_email (external_email),
    ADD CONSTRAINT ck_user_kind_identifier CHECK (
        (user_kind = 'EMPLOYEE' AND emp_no IS NOT NULL) OR (user_kind = 'EXTERNAL' AND email IS NOT NULL)
    );
