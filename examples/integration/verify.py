#!/usr/bin/env python3
"""연동 예제 검증기. 표준 라이브러리만 쓴다.

예제 앱 하나를 로컬 IAM 에 실제로 붙여 보고 다음을 확인한다.
  1. /login → IAM 로그인 → /callback → /me 까지 로그인되고, /me 에 IAM subject ID 와 연결된 로컬 계정이 나온다
  2. /webhooks/iam 이 올바른 서명만 받고(잘못된 서명·오래된 시각은 401), 같은 전달 ID 는 한 번만 처리한다
  3. IAM 에서 로그아웃하면 back-channel 로그아웃으로 앱 세션도 끝난다 (/me 가 401)

사용:  python3 verify.py http://localhost:4101
       python3 verify.py http://localhost:4101 --webhook-only   (IAM 클라이언트 없이 웹훅 처리만)
환경변수(.env.local): IAM_ISSUER, IAM_TEST_LOGIN_ID, IAM_TEST_PASSWORD, WEBHOOK_SECRET
"""
import hashlib
import hmac
import html.parser
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


def load_env(path):
    if not os.path.exists(path):
        return
    for line in open(path, encoding="utf-8"):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


class Browser:
    """localhost 는 포트가 달라도 쿠키를 함께 쓰므로, 포트별로 쿠키를 나눠 둔다 (IAM 과 앱의 세션 쿠키가 섞이지 않게)"""

    def __init__(self):
        self.jars = {}
        self.opener = urllib.request.build_opener(NoRedirect)

    def _jar(self, url):
        p = urllib.parse.urlsplit(url)
        return self.jars.setdefault((p.hostname, p.port), {})

    def request(self, method, url, data=None, headers=None, follow=True):
        for _ in range(25):
            jar = self._jar(url)
            # 실제 브라우저처럼 Accept 를 보낸다 (인증 프록시는 브라우저 요청에만 로그인 화면으로 보낸다)
            # (application/json 은 넣지 않는다: Spring Security 는 JSON 을 받는 요청을 API 호출로 보고 로그인 뒤 돌아갈 곳으로 저장하지 않는다)
            h = {"Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"}
            h.update(headers or {})
            if jar:
                h["Cookie"] = "; ".join(f"{k}={v}" for k, v in jar.items())
            body = data.encode() if isinstance(data, str) else data
            req = urllib.request.Request(url, data=body, method=method, headers=h)
            try:
                res = self.opener.open(req, timeout=15)
                status, rh, content = res.status, res.headers, res.read()
            except urllib.error.HTTPError as e:
                status, rh, content = e.code, e.headers, e.read()
            for c in rh.get_all("Set-Cookie") or []:
                name, _, rest = c.partition("=")
                value = rest.split(";", 1)[0]
                if "max-age=0" in c.lower() or "expires=thu, 01 jan 1970" in c.lower():
                    jar.pop(name.strip(), None)
                else:
                    jar[name.strip()] = value
            if follow and status in (301, 302, 303, 307, 308) and rh.get("Location"):
                url = urllib.parse.urljoin(url, rh["Location"])
                if status in (301, 302, 303):
                    method, data, headers = "GET", None, None
                continue
            return status, url, rh, content.decode("utf-8", "replace")
        raise RuntimeError("리다이렉트가 너무 많습니다")


class FormParser(html.parser.HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._cur = [], None

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "form":
            self._cur = {"action": a.get("action", ""), "inputs": {}}
            self.forms.append(self._cur)
        elif tag == "input" and self._cur is not None and a.get("name"):
            self._cur["inputs"][a["name"]] = a.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form":
            self._cur = None


def form(page, action_suffix):
    p = FormParser()
    p.feed(page)
    for f in p.forms:
        if f["action"].endswith(action_suffix):
            return f
    raise AssertionError(f"{action_suffix} 폼을 찾지 못했습니다")


results = []


def check(name, ok, detail=""):
    results.append((name, ok))
    print(("PASS " if ok else "FAIL ") + name + (f" — {detail}" if detail else ""))
    return ok


def signed(secret, body, ts=None):
    ts = str(ts if ts is not None else int(time.time()))
    sig = "sha256=" + hmac.new(secret.encode(), f"{ts}.{body}".encode(), hashlib.sha256).hexdigest()
    return ts, sig


def main():
    here = os.path.dirname(os.path.abspath(__file__))
    load_env(os.path.join(here, ".env.local"))
    app = sys.argv[1].rstrip("/")
    webhook_only = "--webhook-only" in sys.argv[2:]
    issuer = os.environ.get("IAM_ISSUER", "http://localhost:8080").rstrip("/")
    secret = os.environ["WEBHOOK_SECRET"]
    b = Browser()
    if webhook_only:
        webhooks(b, app, secret)
        return finish()
    login_id, password = os.environ["IAM_TEST_LOGIN_ID"], os.environ["IAM_TEST_PASSWORD"]

    # 1. 로그인
    status, url, _, page = b.request("GET", app + "/login")
    if not check("앱 /login 이 IAM 로그인 화면으로 보낸다", url.startswith(issuer + "/login") and status == 200, url):
        return finish()
    f = form(page, "/login")
    fields = dict(f["inputs"], username=login_id, password=password)
    status, url, _, page = b.request("POST", urllib.parse.urljoin(url, f["action"]), urllib.parse.urlencode(fields),
                                     {"Content-Type": "application/x-www-form-urlencoded"})
    if not check("로그인 뒤 앱으로 돌아와 /me 에 도착한다", url.startswith(app) and status == 200, f"{status} {url}"):
        return finish()
    try:
        me = json.loads(page)
    except ValueError:
        status, _, _, page = b.request("GET", app + "/me")
        me = json.loads(page)
    check("/me 에 IAM subject ID(sub) 가 있다", str(me.get("sub", "")).isdigit(), json.dumps(me, ensure_ascii=False))
    check("/me 에 연결된 로컬 계정이 있다", me.get("localUserId") not in (None, ""), str(me.get("localUserId")))
    status, _, _, _ = b.request("GET", app + "/me")
    check("세션으로 /me 를 다시 볼 수 있다", status == 200, str(status))

    webhooks(b, app, secret)
    back_channel(b, app, issuer)
    finish()


def webhooks(b, app, secret):
    delivery = str(uuid.uuid4().int % 10**9)
    body = json.dumps({"id": str(uuid.uuid4()), "type": "user.status_changed", "occurredAt": "2026-01-01T00:00:00Z",
                       "data": {"subjectId": 999999, "status": "DISABLED"}}, separators=(",", ":"))
    ts, sig = signed(secret, body)
    hdr = {"Content-Type": "application/json", "X-Didrakon-Event": "user.status_changed",
           "X-Didrakon-Delivery": delivery, "X-Didrakon-Timestamp": ts, "X-Didrakon-Signature": sig}
    s1, _, _, _ = b.request("POST", app + "/webhooks/iam", body, hdr, follow=False)
    check("웹훅: 올바른 서명은 2xx", 200 <= s1 < 300, str(s1))
    s2, _, _, r2 = b.request("POST", app + "/webhooks/iam", body, hdr, follow=False)
    check("웹훅: 같은 전달 ID 를 다시 보내도 2xx (중복으로 처리)", 200 <= s2 < 300, f"{s2} {r2[:80]}")
    bad = dict(hdr, **{"X-Didrakon-Signature": "sha256=" + "0" * 64, "X-Didrakon-Delivery": delivery + "1"})
    s3, _, _, _ = b.request("POST", app + "/webhooks/iam", body, bad, follow=False)
    check("웹훅: 잘못된 서명은 401", s3 == 401, str(s3))
    old_ts, old_sig = signed(secret, body, int(time.time()) - 3600)
    stale = dict(hdr, **{"X-Didrakon-Timestamp": old_ts, "X-Didrakon-Signature": old_sig, "X-Didrakon-Delivery": delivery + "2"})
    s4, _, _, _ = b.request("POST", app + "/webhooks/iam", body, stale, follow=False)
    check("웹훅: 5분보다 오래된 시각은 401", s4 == 401, str(s4))


def back_channel(b, app, issuer):
    """IAM 에서 로그아웃하면 back-channel 로그아웃으로 앱 세션도 끝난다"""
    status, url, _, page = b.request("GET", issuer + "/")
    f = form(page, "/logout")
    b.request("POST", urllib.parse.urljoin(url, f["action"]), urllib.parse.urlencode(f["inputs"]),
              {"Content-Type": "application/x-www-form-urlencoded"}, follow=False)
    ended = False
    for _ in range(20):
        status, url, _, _ = b.request("GET", app + "/me", follow=False)
        if status == 401:
            ended = True
            break
        time.sleep(0.5)
    check("IAM 로그아웃 → back-channel 로그아웃으로 앱 세션이 끝난다 (/me 401)", ended, str(status))


def finish():
    failed = [n for n, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} 통과")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
