-- 기본 위험 정책. 점수 합이 80 이상이면 정책과 관계없이 DENY (RiskEngine.DENY_SCORE)
-- 로그인은 DENY 만 막는다. CHALLENGE 는 기록만 남고, MFA 를 등록한 사용자는 원래대로 MFA 를 거친다
INSERT INTO risk_policy (policy_name, risk_type, condition_expression, risk_score, action) VALUES
    ('처음 쓰는 기기로 로그인', 'LOGIN', '{"signal": "NEW_DEVICE"}', 20, 'CHALLENGE'),
    ('업무 시간 밖 로그인', 'LOGIN', '{"signal": "UNUSUAL_TIME", "from": "07:00", "to": "22:00"}', 20, 'ALLOW'),
    ('연속 실패 뒤 로그인', 'LOGIN', '{"signal": "FAILED_LOGIN_BURST", "threshold": 3}', 30, 'CHALLENGE'),
    ('해외 IP 로그인', 'LOGIN', '{"signal": "FOREIGN_IP", "allowedCountries": ["KR"]}', 50, 'CHALLENGE'),
    ('짧은 시간 대량 조회', 'DATA_ACCESS', '{"signal": "MASS_ACCESS", "threshold": 100, "windowSeconds": 60}', 60, 'CHALLENGE'),
    ('업무 시간 밖 임시 권한 요청', 'JIT', '{"signal": "UNUSUAL_TIME", "from": "07:00", "to": "22:00"}', 30, 'APPROVAL'),
    ('업무 시간 밖 비상 접근', 'PRIVILEGE', '{"signal": "UNUSUAL_TIME", "from": "07:00", "to": "22:00"}', 30, 'APPROVAL');
