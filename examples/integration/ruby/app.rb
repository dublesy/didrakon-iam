# DIDRAKON IAM 연동 예제 — Sinatra + openid_connect + jwt.
# 계약은 ../README.md. 사용자·세션·웹훅 전달 기록을 메모리에 둔다 (재시작하면 사라진다).
require "sinatra"
require "base64"
require "openid_connect"
require "jwt"
require "json"
require "net/http"
require "openssl"
require "securerandom"
require "set"

ISSUER = ENV.fetch("IAM_ISSUER", "http://localhost:8080").chomp("/")
CLIENT_ID = ENV.fetch("CLIENT_ID", "sample-ruby")
CLIENT_SECRET = ENV.fetch("CLIENT_SECRET", "change-me")
WEBHOOK_SECRET = ENV.fetch("WEBHOOK_SECRET", "")
APP_URL = ENV.fetch("APP_URL", "http://localhost:4109")
SESSION_COOKIE = "sample_ruby_sid"
BACKCHANNEL_EVENT = "http://schemas.openid.net/event/backchannel-logout"

set :server, :puma
set :bind, "0.0.0.0"
set :port, 4109

# discovery 는 기본으로 https 만 쓴다. 로컬 IAM(http://localhost:8080) 일 때만 http 를 허용한다
SWD.url_builder = URI::HTTP if ISSUER.start_with?("http://")

module IAM
  def self.provider # discovery 문서 (처음 쓸 때 한 번 읽는다)
    @provider ||= OpenIDConnect::Discovery::Provider::Config.discover!(ISSUER)
  end

  def self.client # 요청마다 새로 만든다 (authorization_code 를 담으므로)
    OpenIDConnect::Client.new(
      identifier: CLIENT_ID,
      secret: CLIENT_SECRET,
      redirect_uri: "#{APP_URL}/callback",
      authorization_endpoint: provider.authorization_endpoint,
      token_endpoint: provider.token_endpoint,
      userinfo_endpoint: provider.userinfo_endpoint
    )
  end

  # jwt gem 의 JWKS 로더. 모르는 kid 가 오면 invalidate: true 로 다시 불러 키 교체를 따라간다
  def self.jwks(options = {})
    @jwks = nil if options[:invalidate]
    @jwks ||= JSON.parse(Net::HTTP.get(URI(provider.jwks_uri)))
  end
end

# ── 저장소 (메모리) ─────────────────────────────────────────────────────
LocalUser = Struct.new(:id, :iam_subject_id, :emp_no, :name, :active)
USERS = []          # 실제 시스템에서는 users 테이블 + iam_subject_id 컬럼
SESSIONS = {}       # 세션 ID => { "user", "sid", "id_token" } 또는 로그인 중이면 { "state", "nonce", "code_verifier" }
DELIVERIES = Set.new
LOCK = Mutex.new    # puma 는 여러 스레드로 요청을 처리한다

# iam_subject_id → emp_no → 새로 만들기(JIT). 이메일로는 연결하지 않는다.
def link_account(claims)
  sub, emp_no = claims["sub"], claims["emp_no"]
  LOCK.synchronize do
    user = USERS.find { |u| u.iam_subject_id == sub }
    if user.nil? && emp_no
      user = USERS.find { |u| u.emp_no == emp_no && u.iam_subject_id.nil? }
      user.iam_subject_id = sub if user
    end
    user ||= LocalUser.new(USERS.size + 1, sub, emp_no, claims["name"], true).tap { |u| USERS << u }
    user
  end
end

def end_sessions_where
  LOCK.synchronize { SESSIONS.delete_if { |_, s| yield s } }
end

helpers do
  def current_session
    LOCK.synchronize { SESSIONS[request.cookies[SESSION_COOKIE]] }
  end

  def start_session(data) # 새 세션 ID 를 발급한다 (로그인할 때마다 바꿔 세션 고정을 막는다)
    id = SecureRandom.urlsafe_base64(32)
    LOCK.synchronize { SESSIONS[id] = data }
    response.set_cookie(SESSION_COOKIE, value: id, path: "/", httponly: true, same_site: :lax)
  end

  def end_session
    LOCK.synchronize { SESSIONS.delete(request.cookies[SESSION_COOKIE]) }
    response.delete_cookie(SESSION_COOKIE, path: "/")
  end

  def json_error(status_code, error)
    halt status_code, { "Content-Type" => "application/json" }, { error: error }.to_json
  end
end

# ── 로그인·로그아웃 ─────────────────────────────────────────────────────
get "/login" do
  state, nonce = SecureRandom.urlsafe_base64(32), SecureRandom.urlsafe_base64(32)
  code_verifier = SecureRandom.urlsafe_base64(48)
  code_challenge = Base64.urlsafe_encode64(OpenSSL::Digest::SHA256.digest(code_verifier), padding: false)
  start_session("state" => state, "nonce" => nonce, "code_verifier" => code_verifier)
  redirect IAM.client.authorization_uri(
    scope: %w[openid profile], state: state, nonce: nonce,
    code_challenge: code_challenge, code_challenge_method: "S256"
  ), 302
end

get "/callback" do
  pending = current_session
  json_error 400, "invalid_state" unless pending && pending["state"] &&
                                         Rack::Utils.secure_compare(pending["state"], params["state"].to_s)
  json_error 400, params["error"] if params["error"]
  end_session

  # code 교환 (client_secret_basic + code_verifier)
  client = IAM.client
  client.authorization_code = params["code"]
  token = client.access_token!(:basic, code_verifier: pending["code_verifier"])

  # ID 토큰 검증: decode 가 JWKS 서명(kid)을, verify! 가 iss·aud·exp·nonce 를 본다
  id_token = OpenIDConnect::ResponseObject::IdToken.decode(token.id_token, IAM.provider)
  id_token.verify!(issuer: ISSUER, client_id: CLIENT_ID, nonce: pending["nonce"])
  claims = id_token.raw_attributes # emp_no·roles 같은 IAM claim 까지 그대로 담긴 Hash

  user = link_account(claims)
  json_error 403, "local_user_disabled" unless user.active
  start_session(
    "user" => { "sub" => claims["sub"], "name" => claims["name"], "empNo" => claims["emp_no"],
                "roles" => claims["roles"] || [], "localUserId" => user.id },
    "sid" => claims["sid"],
    "id_token" => token.id_token
  )
  redirect "/me", 302
rescue Rack::OAuth2::Client::Error, OpenIDConnect::ResponseObject::IdToken::InvalidToken, JSON::JWT::Exception => e
  json_error 400, e.message
end

get "/me" do
  s = current_session
  json_error 401, "unauthorized" unless s && s["user"]
  content_type :json
  s["user"].merge("sid" => s["sid"]).to_json
end

get "/logout" do
  id_token = current_session&.fetch("id_token", nil)
  end_session
  redirect "#{IAM.provider.end_session_endpoint}?#{URI.encode_www_form(id_token_hint: id_token)}", 302 if id_token
  content_type :json
  { loggedOut: true }.to_json
end

# ── back-channel 로그아웃 ──────────────────────────────────────────────
post "/backchannel-logout" do
  claims, header = JWT.decode(
    params["logout_token"].to_s, nil, true,
    algorithms: ["RS256"], jwks: IAM.method(:jwks),
    iss: ISSUER, verify_iss: true,
    aud: CLIENT_ID, verify_aud: true,          # aud 가 배열이면 그중 하나가 내 client_id
    verify_iat: true, required_claims: %w[iss aud iat exp], leeway: 60
  )
  raise JWT::DecodeError, "typ 이 logout+jwt 가 아님" unless header["typ"] == "logout+jwt"
  raise JWT::DecodeError, "events 에 back-channel 로그아웃이 없음" unless (claims["events"] || {}).key?(BACKCHANNEL_EVENT)
  raise JWT::DecodeError, "nonce 가 있으면 안 됨" if claims.key?("nonce")
  raise JWT::DecodeError, "sub·sid 가 모두 없음" unless claims["sub"] || claims["sid"]

  if claims["sid"]
    end_sessions_where { |s| s["sid"] == claims["sid"] }
  else
    end_sessions_where { |s| s.dig("user", "sub") == claims["sub"] }
  end
  headers "Cache-Control" => "no-store"
  200
rescue JWT::DecodeError => e # 서명·만료·iss·aud 실패도 모두 DecodeError 의 하위 클래스
  json_error 400, "invalid_logout_token: #{e.message}"
end

# ── 웹훅 ───────────────────────────────────────────────────────────────
post "/webhooks/iam" do
  request.body.rewind
  raw = request.body.read # 다시 직렬화하지 않고 받은 바이트 그대로 서명을 검증한다
  timestamp = request.env["HTTP_X_DIDRAKON_TIMESTAMP"].to_s
  signature = request.env["HTTP_X_DIDRAKON_SIGNATURE"].to_s
  expected = "sha256=" + OpenSSL::HMAC.hexdigest("SHA256", WEBHOOK_SECRET, "#{timestamp}.#{raw}")
  json_error 401, "bad_signature" if WEBHOOK_SECRET.empty? || !Rack::Utils.secure_compare(expected, signature)
  json_error 401, "stale_timestamp" unless timestamp.match?(/\A\d+\z/) && (Time.now.to_i - timestamp.to_i).abs <= 300

  content_type :json
  delivery = request.env["HTTP_X_DIDRAKON_DELIVERY"].to_s
  first_time = LOCK.synchronize { DELIVERIES.add?(delivery) }
  halt 200, { duplicate: true }.to_json unless first_time # 이미 처리한 전달

  event = JSON.parse(raw)
  data = event["data"] || {}
  if event["type"] == "user.status_changed" && data["status"] == "RETIRED"
    sub = data["subjectId"].to_s # 본문의 subjectId 는 숫자, 토큰의 sub 는 문자열
    LOCK.synchronize { USERS.each { |u| u.active = false if u.iam_subject_id == sub } }
    end_sessions_where { |s| s.dig("user", "sub") == sub }
  end
  { ok: true }.to_json
end
