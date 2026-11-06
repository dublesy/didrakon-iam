# 데이터 이관 가이드 (MySQL · PostgreSQL · Supabase)

기존 시스템의 사용자·권한 데이터를 IAM 과 잇는 방법. 공통 개념은 [연동 가이드](README.md#5-계정-연결)를 먼저 읽는다.

**옮기는 것과 옮기지 않는 것**

| 데이터 | 처리 |
|---|---|
| 사람 (임직원) | IAM 에는 HR 연동으로 이미 있다. 시스템 계정에 **IAM subject ID 만 연결**한다 |
| 사람 (외부·협력사·고객사) | IAM 에 외부 사용자로 등록한 뒤 연결한다 |
| 비밀번호 | **옮기지 않는다.** 로그인은 IAM 이 하므로 전환이 끝나면 폐기한다 |
| 공용·배치 계정 | 사람이 아니므로 IAM 서비스 계정(client credentials, API 키)으로 바꾼다 |
| 시스템 권한 | 1·2단계: 그대로 둔다. 3단계: IAM 역할 할당으로 옮긴다 ([아래](#권한-이관-3단계)) |
| 업무 데이터 | 그대로 둔다. 작성자·담당자 컬럼은 로컬 사용자 ID 를 그대로 가리키므로 바꿀 필요 없다 |

## 1. 연결 컬럼 추가

로컬 사용자 테이블에 IAM `sub` 를 저장할 컬럼을 둔다. `sub` 는 OIDC 표준상 **문자열**이므로 문자열로 저장한다 (지금은 숫자지만 형식을 가정하지 않는다).

**MySQL**
```sql
ALTER TABLE users
    ADD COLUMN iam_subject_id VARCHAR(64) NULL COMMENT 'IAM sub. 로그인은 이 값으로만 찾는다',
    ADD COLUMN iam_linked_at  DATETIME(6) NULL,
    ADD UNIQUE KEY uk_users_iam_subject_id (iam_subject_id);
```

**PostgreSQL**
```sql
ALTER TABLE users
    ADD COLUMN iam_subject_id varchar(64),
    ADD COLUMN iam_linked_at  timestamptz;
CREATE UNIQUE INDEX uk_users_iam_subject_id ON users (iam_subject_id);
COMMENT ON COLUMN users.iam_subject_id IS 'IAM sub. 로그인은 이 값으로만 찾는다';
```

- 이관 중에는 비어 있는 행이 있으므로 `NULL` 을 허용한다. UNIQUE 는 NULL 을 여러 개 허용하므로 그대로 둔다.
- 한 사람에게 계정이 둘 이상이면(퇴사 후 재입사, 중복 생성) UNIQUE 에 걸린다. 사람이 하나로 합치거나 하나를 끈다.

## 2. 일괄 연결

### 계정 연결 조회 API

```
POST {IAM}/api/v1/users/lookup
Authorization: Bearer <관리 콘솔에서 받은 관리자 토큰>   또는   X-API-Key: <서비스 계정 키>

{"empNos": ["D-001", "D-002"], "emails": ["partner@example.com"]}
```

```json
{"data": [
  {"key": "D-001", "matchedBy": "EMP_NO", "matches": [{"subjectId": 2, "empNo": "D-001", "name": "김하늘", "status": "ACTIVE", ...}]},
  {"key": "D-002", "matchedBy": "EMP_NO", "matches": []},
  {"key": "partner@example.com", "matchedBy": "EMAIL", "matches": [{...}, {...}]}
]}
```

- 사번은 하나에만 맞는다. 이메일은 대소문자를 무시하며, 임직원과 외부 사용자가 같은 이메일이면 **여러 명**이 나온다 → 사람이 골라야 한다.
- 한 번에 1000건까지. 개인정보가 URL·로그에 남지 않도록 본문으로 보낸다.
- `/api` 는 관리 콘솔(`iam-admin`)에 발급된 사용자 토큰만 받는다. 연동 시스템이 자기 로그인으로 받은 토큰은 쓸 수 없으니 서비스 계정 API 키를 쓴다.
- 사용자 조회 **전체 범위** 권한이 필요하다 (조직 단위 관리자는 403). 이관용으로는 사용자 조회(`iam.identity.user` READ) 권한만 준 역할을 만들어 서비스 계정에 할당하고, 그 계정의 API 키를 쓰는 것을 권한다. 작업이 끝나면 키를 폐기한다.

### 연결 도구

[`examples/integration/tools/link_accounts.py`](../../examples/integration/tools/link_accounts.py) 가 위 API 로 CSV 를 처리해 SQL 을 만든다 (Python 3 표준 라이브러리만 사용).

```bash
# 1) 로컬 사용자 내보내기 (로컬 ID, 사번, 이메일)
mysql  -e "SELECT id AS local_id, emp_no, email FROM users WHERE iam_subject_id IS NULL" --batch erp > users.tsv
psql   -c "\copy (SELECT id AS local_id, emp_no, email FROM users WHERE iam_subject_id IS NULL) TO 'users.csv' CSV HEADER" erp

# 2) 맞추기 (IAM_API_KEY 또는 IAM_TOKEN 환경변수)
python3 link_accounts.py users.csv --issuer https://iam.example.com --dialect postgres --table users --id-column id

# 3) 결과 확인 뒤 적용
#    linked.sql      확실히 맞은 계정의 UPDATE 문
#    review.csv      사람이 봐야 할 것 (못 찾음, 이메일 중복, IAM 에서 ACTIVE 아님)
psql erp -f linked.sql
```

맞추는 규칙: **사번이 있으면 사번으로만** 맞춘다. 사번이 없을 때만 이메일로 찾고, 정확히 한 명일 때만 자동 연결한다. IAM 에서 `ACTIVE` 가 아닌 사람(퇴사·사용 중지)은 연결하지 않고 `review.csv` 로 보낸다 — 그 로컬 계정은 끄는 대상이다.

### 첫 로그인 때 연결 (보조)

일괄 연결에서 빠진 사람은 로그인할 때 연결할 수 있다. **사번이 있을 때만** 쓴다.

```sql
-- 1. sub 로 찾기
SELECT * FROM users WHERE iam_subject_id = :sub;
-- 2. 없으면 토큰의 emp_no 로 찾아 연결 (이미 다른 sub 와 연결된 계정은 건드리지 않는다)
UPDATE users SET iam_subject_id = :sub, iam_linked_at = now()
 WHERE emp_no = :emp_no AND iam_subject_id IS NULL;
```

## 3. 전환 뒤 정리

```sql
-- 비밀번호 로그인 막기: 비상용 관리자 계정 하나만 남긴다
UPDATE users SET password_hash = NULL WHERE id <> :break_glass_admin_id;

-- 연결되지 않은 채 남은 계정: 끄고 목록을 보관한다 (지우지 않는다)
UPDATE users SET active = false WHERE iam_subject_id IS NULL AND id <> :break_glass_admin_id;
```

비밀번호 해시 폐기는 병행 기간이 끝나고 되돌릴 일이 없을 때 한다.

## 권한 이관 (3단계)

1. **대응표 만들기**: 시스템 역할 → IAM 리소스·권한·역할. 시스템마다 리소스 키를 `{clientCode}` 아래에 둔다 (예: `erp` 클라이언트의 `payment` 리소스, `APPROVE` 권한 → `ERP_PAYMENT_APPROVER` 역할)
2. **먼저 정리**: 옮기기 전에 시스템 안에서 안 쓰는 권한을 걷어낸다. 옮긴 뒤 IAM 접근 재검토를 한 번 돌린다
3. **할당 옮기기**: 로컬 권한 부여 내역을 내보내 `POST /api/v1/assignments` (`subjectId`, `roleId`, `scopeId`, `validUntil`, `reason`) 로 넣는다. `reason` 에 "ERP 이관" 같은 출처를 남기면 감사 기록에서 구분된다
4. **판단 바꾸기**: 시스템은 로컬 권한 테이블 대신 토큰 `roles` 나 `/api/v1/authz/check` 로 판단한다
5. **로컬 권한 테이블은 읽기 전용으로 남겼다가** 병행 기간 뒤 정리한다

## Supabase

Supabase 를 DB·API 로 쓰는 시스템은 **Third-Party Auth (Custom OIDC)** 로 IAM 토큰을 그대로 받아 RLS 에 쓸 수 있다 ([Supabase 문서](https://supabase.com/docs/guides/auth/third-party/custom-oidc)).

> 로컬 IAM(`http://localhost`)으로는 확인하지 못했다. Supabase 는 issuer 가 **https 이고 인터넷에서 닿아야** 한다. 아래는 Supabase 문서와 IAM 토큰 형식을 맞춘 것이다.

**IAM 쪽**
- 그 시스템의 클라이언트에서 **Supabase 호환**을 켠다 → 접근·ID 토큰에 `role: "authenticated"` 가 들어간다 (Supabase 는 이 값이 없으면 익명 `anon` 으로 본다)
- 토큰은 RS256 이고 헤더에 `kid` 가 있다 (Supabase 요구 사항)

**Supabase 쪽**
1. `Authentication → Sign In / Providers → Third-Party Auth` 에서 Custom OIDC 로 IAM issuer(`https://iam.example.com`)를 추가한다
2. 클라이언트에서 IAM 토큰을 넘긴다
   ```js
   const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
     accessToken: async () => session?.accessToken ?? null, // IAM 접근 토큰 (만료 전에 refresh 한다)
   });
   ```
3. RLS 는 `auth.uid()` 대신 **`auth.jwt()->>'sub'`** 를 쓴다. `auth.uid()` 는 `sub` 를 uuid 로 바꾸려다 실패한다 (IAM `sub` 는 uuid 가 아니다). 사용자 컬럼은 `text` 로 둔다

```sql
-- 본인 행만
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own rows" ON documents FOR ALL TO authenticated
  USING (owner_sub = (auth.jwt() ->> 'sub'))
  WITH CHECK (owner_sub = (auth.jwt() ->> 'sub'));

-- 믿는 발급자만 (여러 issuer 를 등록했거나 Supabase Auth 도 같이 쓸 때 필수). restrictive 를 빼면 효과가 없다
CREATE POLICY "only iam" ON documents AS RESTRICTIVE FOR ALL TO authenticated
  USING ((auth.jwt() ->> 'iss') = 'https://iam.example.com');

-- IAM 역할로 판단 (roles 는 토큰 발급 시점 값, 10분 안에 바뀐 것은 반영 안 됨)
CREATE POLICY "hr can read" ON employees FOR SELECT TO authenticated
  USING ((auth.jwt() -> 'roles') ? 'HR_MANAGER');
```

**Supabase Auth 를 쓰던 시스템이라면**
- 기존 테이블이 `auth.users.id`(uuid)를 가리키고 있다. 프로필 테이블에 `iam_subject_id text` 를 두고 [일괄 연결](#2-일괄-연결)로 채운 뒤, RLS 를 `auth.uid()` 에서 `iam_subject_id = auth.jwt()->>'sub'` 로 바꾼다.
- 전환 기간에 두 방식이 섞이면 `iss` 로 구분하는 restrictive 정책을 꼭 둔다.
- Supabase 문서상 제약: 키 교체 반영에 최대 30분, Supabase CLI 로컬 환경(`config.toml`)에서는 Custom OIDC 를 쓸 수 없다.
