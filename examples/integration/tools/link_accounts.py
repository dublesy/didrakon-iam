#!/usr/bin/env python3
"""기존 시스템 계정을 IAM 사용자(subject ID)와 잇는 일회성 도구. 표준 라이브러리만 쓴다.

입력: 로컬 사용자 CSV·TSV (머리글에 local_id, emp_no, email. emp_no·email 은 비어도 된다)
출력: linked.sql (확실히 맞은 계정의 UPDATE 문), review.csv (사람이 봐야 할 것)

규칙
  - 사번이 있으면 사번으로만 맞춘다
  - 사번이 없을 때만 이메일로 찾고, 정확히 한 명일 때만 연결한다
  - IAM 에서 ACTIVE 가 아닌 사람은 연결하지 않는다 (그 로컬 계정은 끌 대상)

인증: 환경변수 IAM_API_KEY (X-API-Key) 또는 IAM_TOKEN (Bearer). 사용자 조회 전체 범위 권한이 필요하다

예: python3 link_accounts.py users.csv --issuer https://iam.example.com --dialect mysql --table users --id-column id
"""
import argparse
import csv
import json
import os
import sys
import urllib.error
import urllib.request

BATCH = 500


def read_rows(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        sample = f.read(4096)
        f.seek(0)
        dialect = csv.excel_tab if "\t" in sample.splitlines()[0] else csv.excel
        rows = list(csv.DictReader(f, dialect=dialect))
    for r in rows:
        if "local_id" not in r:
            sys.exit("머리글에 local_id 가 필요합니다 (local_id, emp_no, email)")
        for k in ("emp_no", "email"):
            v = (r.get(k) or "").strip()
            r[k] = "" if v.upper() == "NULL" else v
    return rows


def lookup(issuer, emp_nos, emails):
    body = json.dumps({"empNos": emp_nos, "emails": emails}).encode()
    headers = {"Content-Type": "application/json"}
    if os.environ.get("IAM_API_KEY"):
        headers["X-API-Key"] = os.environ["IAM_API_KEY"]
    elif os.environ.get("IAM_TOKEN"):
        headers["Authorization"] = "Bearer " + os.environ["IAM_TOKEN"]
    else:
        sys.exit("IAM_API_KEY 또는 IAM_TOKEN 환경변수가 필요합니다")
    req = urllib.request.Request(issuer.rstrip("/") + "/api/v1/users/lookup", data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as res:
            return json.load(res)["data"]
    except urllib.error.HTTPError as e:
        sys.exit(f"조회 실패 HTTP {e.code}: {e.read().decode(errors='replace')[:300]}")


def resolve_all(issuer, rows):
    emp_nos = sorted({r["emp_no"] for r in rows if r["emp_no"]})
    emails = sorted({r["email"].lower() for r in rows if not r["emp_no"] and r["email"]})
    by_emp, by_email = {}, {}
    for i in range(0, max(len(emp_nos), len(emails)), BATCH):
        for m in lookup(issuer, emp_nos[i:i + BATCH], emails[i:i + BATCH]):
            (by_emp if m["matchedBy"] == "EMP_NO" else by_email)[m["key"].lower() if m["matchedBy"] == "EMAIL" else m["key"]] = m["matches"]
    return by_emp, by_email


def quote(value, dialect):
    s = str(value).replace("'", "''")
    if dialect == "mysql":
        s = s.replace("\\", "\\\\")
    return f"'{s}'"


def main():
    p = argparse.ArgumentParser(description="로컬 계정을 IAM subject ID 와 잇는 SQL 을 만든다")
    p.add_argument("input")
    p.add_argument("--issuer", required=True)
    p.add_argument("--dialect", choices=["mysql", "postgres"], required=True)
    p.add_argument("--table", default="users")
    p.add_argument("--id-column", default="id")
    p.add_argument("--out-dir", default=".")
    a = p.parse_args()

    rows = read_rows(a.input)
    by_emp, by_email = resolve_all(a.issuer, rows)
    now = "NOW(6)" if a.dialect == "mysql" else "now()"
    linked, review, seen = [], [], {}
    for r in rows:
        if r["emp_no"]:
            matches, by = by_emp.get(r["emp_no"], []), "EMP_NO"
        elif r["email"]:
            matches, by = by_email.get(r["email"].lower(), []), "EMAIL"
        else:
            review.append((r["local_id"], "", "", "NO_KEY", "사번·이메일이 모두 없음"))
            continue
        key = r["emp_no"] or r["email"]
        if not matches:
            review.append((r["local_id"], key, "", "NOT_FOUND", "IAM 에 없음 (퇴사자·외부 사용자 미등록?)"))
        elif len(matches) > 1:
            ids = " ".join(str(m["subjectId"]) for m in matches)
            review.append((r["local_id"], key, ids, "AMBIGUOUS", "이메일이 여러 사람에게 맞음"))
        elif matches[0]["status"] != "ACTIVE":
            review.append((r["local_id"], key, matches[0]["subjectId"], "NOT_ACTIVE", f"IAM 상태 {matches[0]['status']} — 로컬 계정을 끌 대상"))
        else:
            sid = str(matches[0]["subjectId"])
            if sid in seen:
                review.append((r["local_id"], key, sid, "DUPLICATE", f"로컬 계정 {seen[sid]} 와 같은 사람"))
                continue
            seen[sid] = r["local_id"]
            linked.append(
                f"UPDATE {a.table} SET iam_subject_id = {quote(sid, a.dialect)}, iam_linked_at = {now} "
                f"WHERE {a.id_column} = {quote(r['local_id'], a.dialect)} AND iam_subject_id IS NULL; -- {by}"
            )

    with open(os.path.join(a.out_dir, "linked.sql"), "w", encoding="utf-8") as f:
        f.write("-- link_accounts.py 결과. 확인한 뒤 적용한다\nBEGIN;\n" + "\n".join(linked) + "\nCOMMIT;\n")
    with open(os.path.join(a.out_dir, "review.csv"), "w", newline="", encoding="utf-8-sig") as f:
        w = csv.writer(f)
        w.writerow(["local_id", "key", "iam_subject_id", "reason", "detail"])
        w.writerows(review)
    print(f"연결 {len(linked)}건 → linked.sql, 확인 필요 {len(review)}건 → review.csv (전체 {len(rows)}건)")


if __name__ == "__main__":
    main()
