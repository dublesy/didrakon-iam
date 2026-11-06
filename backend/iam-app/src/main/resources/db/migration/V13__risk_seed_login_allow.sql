-- V9 기본 로그인 위험 정책 중 흔한 신호 두 개의 조치를 CHALLENGE → ALLOW(점수만 더함)로 낮춘다.
-- 로그인은 이제 CHALLENGE 에 추가 인증을 요구하고, 확인된 MFA 가 없으면 막는다 (iam.risk.block-challenge-without-mfa).
-- 새 브라우저(User-Agent)·연속 실패는 흔한 신호라 단독으로 막으면 MFA 없는 사용자가 영구 차단된다
-- (막힌 로그인은 세션을 남기지 않아 기기가 계속 "처음"이고, 실패 횟수도 줄지 않는다). 점수에는 계속 반영되고,
-- 해외 IP 같은 강한 신호만 추가 인증을 요구한다. V9 머리 주석("CHALLENGE 는 기록만")은 이 버전으로 대체된다.
-- 운영자가 이름·조건·점수·조치를 바꾼 정책은 건드리지 않는다.
UPDATE risk_policy
SET action = 'ALLOW'
WHERE risk_type = 'LOGIN'
  AND action = 'CHALLENGE'
  AND (
        (policy_name = '처음 쓰는 기기로 로그인' AND risk_score = 20
            AND condition_expression = CAST('{"signal": "NEW_DEVICE"}' AS JSON))
     OR (policy_name = '연속 실패 뒤 로그인' AND risk_score = 30
            AND condition_expression = CAST('{"signal": "FAILED_LOGIN_BURST", "threshold": 3}' AS JSON))
  );
