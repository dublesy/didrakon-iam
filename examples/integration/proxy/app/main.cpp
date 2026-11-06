// DIDRAKON IAM 연동 예제: 고칠 수 없는 C++ 시스템 앞에 인증 프록시(Apache httpd + mod_auth_openidc)를 둔다.
// 계약은 ../../README.md, 공통 규칙은 docs/integration/README.md 를 따른다.
//
// 이 앱에는 OIDC 코드가 없다. 로그인·토큰 검증·세션·back-channel 로그아웃은 프록시가 하고,
// 앱은 프록시가 넘겨준 OIDC_CLAIM_* 헤더만 읽는다. 그래서 앱은 프록시를 거쳐서만 닿아야 한다 (127.0.0.1 에만 연다).
// 사용자·처리한 웹훅은 메모리에 둔다. 실제 시스템은 DB 를 쓴다.
#include <httplib.h>
#include <nlohmann/json.hpp>
#include <openssl/crypto.h>
#include <openssl/hmac.h>

#include <cstdlib>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_set>
#include <vector>

using json = nlohmann::json;

constexpr long kWebhookMaxClockSkew = 300;  // 초

// 이 시스템의 사용자. iam_subject_id 가 IAM sub 와 잇는 키다.
struct LocalUser {
    int id;
    std::string iam_subject_id;
    std::string emp_no;
    std::string name;
    bool active = true;
};

std::mutex mu;
// 미리 있던 로컬 계정 (iam_subject_id 가 비어 있어 첫 로그인 때 사번으로 연결된다)
std::vector<LocalUser> users = {{1, "", "D-001", "기존 사용자", true}};
std::unordered_set<std::string> deliveries;  // 처리한 X-Didrakon-Delivery

// sub 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다 (JIT). 이메일로는 연결하지 않는다
LocalUser link_account(const std::string& sub, const std::string& emp_no, const std::string& name) {
    std::lock_guard<std::mutex> lock(mu);
    for (auto& u : users)
        if (u.iam_subject_id == sub) return u;
    if (!emp_no.empty())
        for (auto& u : users)
            if (u.iam_subject_id.empty() && u.emp_no == emp_no) {
                u.iam_subject_id = sub;
                return u;
            }
    users.push_back({static_cast<int>(users.size()) + 1, sub, emp_no, name, true});
    return users.back();
}

std::vector<std::string> split(const std::string& s, char delim) {
    std::vector<std::string> out;
    std::stringstream ss(s);
    for (std::string item; std::getline(ss, item, delim);)
        if (!item.empty()) out.push_back(item);
    return out;
}

void reply_json(httplib::Response& res, int status, const json& body) {
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

// ---- /me: 프록시가 넘긴 claim 헤더를 읽는다 ----

void me(const httplib::Request& req, httplib::Response& res) {
    // 프록시가 로그인하지 않은 요청은 401 로 막지만, 헤더가 없으면 앱도 한 번 더 막는다
    std::string sub = req.get_header_value("OIDC_CLAIM_sub");
    if (sub.empty()) return reply_json(res, 401, {{"error", "unauthorized"}});

    std::string name = req.get_header_value("OIDC_CLAIM_name");
    std::string emp_no = req.get_header_value("OIDC_CLAIM_emp_no");
    std::string sid = req.get_header_value("OIDC_CLAIM_sid");
    LocalUser user = link_account(sub, emp_no, name);
    // 퇴사 웹훅으로 끈 계정. 프록시 세션이 남아 있어도 앱이 막는다
    if (!user.active) return reply_json(res, 401, {{"error", "이 시스템에서 사용 중지된 계정입니다"}});

    reply_json(res, 200, {
        {"sub", sub},
        {"name", name},
        {"empNo", emp_no.empty() ? json(nullptr) : json(emp_no)},
        {"roles", split(req.get_header_value("OIDC_CLAIM_roles"), ',')},  // 배열 claim 은 쉼표로 이어 온다
        {"localUserId", user.id},
        {"sid", sid.empty() ? json(nullptr) : json(sid)},
    });
}

// ---- 웹훅 ----

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
    unsigned char mac[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
         reinterpret_cast<const unsigned char*>(data.data()), data.size(), mac, &len);
    std::ostringstream hex;
    for (unsigned int i = 0; i < len; i++) hex << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(mac[i]);
    return hex.str();
}

bool valid_signature(const std::string& secret, const std::string& timestamp, const std::string& body,
                     const std::string& signature) {
    if (secret.empty()) return false;
    // 받은 바이트 그대로 서명한다. 길이가 다르면 바로 거절하고, 같으면 상수 시간으로 비교한다
    std::string expected = "sha256=" + hmac_sha256_hex(secret, timestamp + "." + body);
    return signature.size() == expected.size() &&
           CRYPTO_memcmp(signature.data(), expected.data(), expected.size()) == 0;
}

void webhook(const std::string& secret, const httplib::Request& req, httplib::Response& res) {
    std::string ts = req.get_header_value("X-Didrakon-Timestamp");
    if (!valid_signature(secret, ts, req.body, req.get_header_value("X-Didrakon-Signature")))
        return reply_json(res, 401, {{"error", "bad signature"}});
    char* end = nullptr;
    long sent = std::strtol(ts.c_str(), &end, 10);
    if (ts.empty() || *end != '\0' || std::labs(std::time(nullptr) - sent) > kWebhookMaxClockSkew)
        return reply_json(res, 401, {{"error", "stale timestamp"}});

    {
        std::lock_guard<std::mutex> lock(mu);
        if (!deliveries.insert(req.get_header_value("X-Didrakon-Delivery")).second)
            return reply_json(res, 200, {{"duplicate", true}});
    }

    json event = json::parse(req.body, nullptr, /*allow_exceptions=*/false);
    if (event.is_object() && event.value("type", "") == "user.status_changed" && event["data"].is_object() &&
        event["data"].value("status", "") == "RETIRED") {
        std::string sub = event["data"]["subjectId"].dump();  // 숫자로 온다. sub 는 같은 숫자의 문자열
        std::lock_guard<std::mutex> lock(mu);
        for (auto& u : users)
            if (u.iam_subject_id == sub) u.active = false;  // 실제 시스템은 권한도 모두 회수한다
        // 프록시 세션은 남는다: 퇴사·비밀번호 변경 같은 사용자 단위 back-channel 로그아웃은 sid 없이 sub 만 담아 오는데,
        // mod_auth_openidc 는 sub 로 세션을 찾지 못한다. 그래서 /me 가 매 요청 로컬 계정을 확인한다 (docs/integration/proxy.md 주의할 점)
    }
    reply_json(res, 200, {{"ok", true}});
}

int main() {
    const char* secret_env = std::getenv("WEBHOOK_SECRET");
    std::string secret = secret_env ? secret_env : "";

    httplib::Server server;
    // /login 은 프록시가 로그인을 시키는 보호 주소. 여기까지 왔으면 로그인한 것이므로 /me 로 보낸다
    server.Get("/login", [](const httplib::Request&, httplib::Response& res) { res.set_redirect("/me"); });
    server.Get("/me", me);
    server.Post("/webhooks/iam", [&secret](const httplib::Request& req, httplib::Response& res) { webhook(secret, req, res); });

    // 프록시만 닿도록 루프백에만 연다. 밖에서 OIDC_CLAIM_* 헤더를 꾸며 바로 부르지 못하게 한다
    std::cout << "sample-proxy app: http://127.0.0.1:9000 (프록시 뒤)" << std::endl;
    server.listen("127.0.0.1", 9000);
}
