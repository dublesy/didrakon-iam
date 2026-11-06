// DIDRAKON IAM 연동 예제 (Go + go-oidc + x/oauth2).
// 계약은 ../README.md, 공통 규칙은 docs/integration/README.md 를 따른다.
// 사용자·세션·처리한 웹훅은 메모리에 둔다. 실제 시스템은 DB 를 쓴다.
package main

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

const (
	cookieName          = "app_session"
	backchannelEvent    = "http://schemas.openid.net/event/backchannel-logout"
	webhookMaxClockSkew = 300 // 초
)

// LocalUser 는 이 시스템의 사용자. IAMSubjectID 가 IAM sub 와 잇는 키다.
type LocalUser struct {
	ID           int
	IAMSubjectID string
	EmpNo        string
	Name         string
	Active       bool
}

// Session 은 서버에 두는 세션. 로그인 전에는 state·nonce·PKCE 만, 로그인 뒤에는 사용자 정보를 담는다.
type Session struct {
	State, Nonce, Verifier string

	Sub, Name, EmpNo, Sid, IDToken string
	Roles                          []string
	LocalUserID                    int
}

type App struct {
	clientID      string
	webhookSecret []byte
	oauth         oauth2.Config
	idVerifier    *oidc.IDTokenVerifier
	endSessionURL string

	mu         sync.Mutex
	sessions   map[string]*Session // 쿠키 값 → 세션
	users      []*LocalUser
	deliveries map[string]bool // 처리한 X-Didrakon-Delivery
}

func main() {
	issuer := env("IAM_ISSUER", "http://localhost:8080")
	port := env("PORT", "4105")
	baseURL := env("APP_BASE_URL", "http://localhost:"+port)
	clientID := env("CLIENT_ID", "sample-go")

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer) // discovery 문서를 읽고 issuer 가 같은지 확인한다
	if err != nil {
		log.Fatalf("IAM discovery 실패: %v", err)
	}
	var meta struct {
		EndSession string `json:"end_session_endpoint"`
	}
	_ = provider.Claims(&meta)

	app := &App{
		clientID:      clientID,
		webhookSecret: []byte(os.Getenv("WEBHOOK_SECRET")),
		oauth: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: env("CLIENT_SECRET", "dummy-secret"),
			Endpoint:     provider.Endpoint(), // 토큰 교환은 client_secret_basic
			RedirectURL:  baseURL + "/callback",
			Scopes:       []string{oidc.ScopeOpenID, "profile"},
		},
		// 서명(JWKS, RS256)·iss·aud·exp 를 검증한다. nonce 는 콜백에서 직접 비교한다
		idVerifier:    provider.Verifier(&oidc.Config{ClientID: clientID}),
		endSessionURL: meta.EndSession,
		sessions:      map[string]*Session{},
		// 미리 있던 로컬 계정 (iam_subject_id 가 비어 있어 첫 로그인 때 사번으로 연결된다)
		users:      []*LocalUser{{ID: 1, EmpNo: "D-001", Name: "기존 사용자", Active: true}},
		deliveries: map[string]bool{},
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", app.login)
	mux.HandleFunc("GET /callback", app.callback)
	mux.HandleFunc("GET /me", app.me)
	mux.HandleFunc("GET /logout", app.logout)
	mux.HandleFunc("POST /backchannel-logout", app.backchannelLogout)
	mux.HandleFunc("POST /webhooks/iam", app.webhook)

	log.Printf("sample-go: %s (client_id=%s, issuer=%s)", baseURL, clientID, issuer)
	log.Fatal(http.ListenAndServe(":"+port, mux))
}

// ---- 로그인 ----

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	s := &Session{State: randomString(), Nonce: randomString(), Verifier: oauth2.GenerateVerifier()}
	a.startSession(w, s)
	authURL := a.oauth.AuthCodeURL(s.State,
		oidc.Nonce(s.Nonce),
		oauth2.S256ChallengeOption(s.Verifier))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (a *App) callback(w http.ResponseWriter, r *http.Request) {
	id, pending := a.currentSession(r)
	if pending == nil || pending.State == "" || r.URL.Query().Get("state") != pending.State {
		http.Error(w, "state 가 맞지 않습니다", http.StatusBadRequest)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "IAM 로그인 실패: "+e, http.StatusUnauthorized)
		return
	}

	token, err := a.oauth.Exchange(r.Context(), r.URL.Query().Get("code"), oauth2.VerifierOption(pending.Verifier))
	if err != nil {
		http.Error(w, "code 교환 실패", http.StatusUnauthorized)
		log.Printf("code 교환 실패: %v", err)
		return
	}
	rawIDToken, _ := token.Extra("id_token").(string)
	idToken, err := a.idVerifier.Verify(r.Context(), rawIDToken)
	if err != nil || idToken.Nonce != pending.Nonce {
		http.Error(w, "ID 토큰 검증 실패", http.StatusUnauthorized)
		log.Printf("ID 토큰 검증 실패: %v", err)
		return
	}
	var claims struct {
		Name  string   `json:"name"`
		EmpNo string   `json:"emp_no"`
		Roles []string `json:"roles"`
		Sid   string   `json:"sid"`
	}
	if err := idToken.Claims(&claims); err != nil {
		http.Error(w, "ID 토큰 claim 오류", http.StatusUnauthorized)
		return
	}

	user := a.linkAccount(idToken.Subject, claims.EmpNo, claims.Name)
	if !user.Active {
		http.Error(w, "사용이 중지된 계정입니다", http.StatusForbidden)
		return
	}

	// 로그인하면 세션 ID 를 새로 만든다 (세션 고정 공격 방지)
	a.endSession(id)
	a.startSession(w, &Session{
		Sub: idToken.Subject, Name: claims.Name, EmpNo: claims.EmpNo, Roles: claims.Roles,
		Sid: claims.Sid, IDToken: rawIDToken, LocalUserID: user.ID,
	})
	http.Redirect(w, r, "/me", http.StatusFound)
}

// linkAccount: iam_subject_id 로 찾고, 없으면 사번으로 찾아 연결하고, 그래도 없으면 만든다 (JIT).
// 이메일로는 연결하지 않는다.
func (a *App) linkAccount(sub, empNo, name string) *LocalUser {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if u.IAMSubjectID == sub {
			return u
		}
	}
	if empNo != "" {
		for _, u := range a.users {
			if u.IAMSubjectID == "" && u.EmpNo == empNo {
				u.IAMSubjectID = sub
				return u
			}
		}
	}
	u := &LocalUser{ID: len(a.users) + 1, IAMSubjectID: sub, EmpNo: empNo, Name: name, Active: true}
	a.users = append(a.users, u)
	return u
}

func (a *App) me(w http.ResponseWriter, r *http.Request) {
	_, s := a.currentSession(r)
	if s == nil || s.Sub == "" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"sub": s.Sub, "name": s.Name, "empNo": s.EmpNo, "roles": s.Roles,
		"localUserId": s.LocalUserID, "sid": s.Sid,
	})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	id, s := a.currentSession(r)
	a.endSession(id)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Path: "/", MaxAge: -1, HttpOnly: true})
	if s == nil || s.IDToken == "" || a.endSessionURL == "" {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	// IAM 로그인 세션까지 끝낸다. post_logout_redirect_uri 를 쓰려면 IAM 에 등록한 값이어야 한다
	http.Redirect(w, r, a.endSessionURL+"?id_token_hint="+url.QueryEscape(s.IDToken), http.StatusFound)
}

// ---- back-channel 로그아웃 ----

func (a *App) backchannelLogout(w http.ResponseWriter, r *http.Request) {
	raw := r.PostFormValue("logout_token")
	sub, sid, err := a.verifyLogoutToken(r.Context(), raw)
	if err != nil {
		log.Printf("logout_token 거부: %v", err)
		http.Error(w, "invalid logout_token", http.StatusBadRequest)
		return
	}
	a.mu.Lock()
	for id, s := range a.sessions {
		// sid 가 있으면 그 IAM 로그인 세션 하나만, 없으면 sub 의 세션 모두
		if (sid != "" && s.Sid == sid) || (sid == "" && s.Sub == sub) {
			delete(a.sessions, id)
		}
	}
	a.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
}

func (a *App) verifyLogoutToken(ctx context.Context, raw string) (sub, sid string, err error) {
	// 헤더 typ 확인 (ID 토큰을 로그아웃 토큰으로 재사용하지 못하게)
	header, _, ok := strings.Cut(raw, ".")
	if !ok {
		return "", "", errors.New("JWT 형식이 아닙니다")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(header)
	var h struct {
		Typ string `json:"typ"`
	}
	if err != nil || json.Unmarshal(headerJSON, &h) != nil || h.Typ != "logout+jwt" {
		return "", "", errors.New("typ 가 logout+jwt 가 아닙니다")
	}
	// 서명(JWKS)·iss·aud·exp 는 ID 토큰과 같은 검증기로
	t, err := a.idVerifier.Verify(ctx, raw)
	if err != nil {
		return "", "", err
	}
	var c struct {
		Sid    string          `json:"sid"`
		Nonce  *string         `json:"nonce"`
		Events map[string]any  `json:"events"`
		Iat    json.RawMessage `json:"iat"`
	}
	if err := t.Claims(&c); err != nil {
		return "", "", err
	}
	switch {
	case c.Iat == nil:
		return "", "", errors.New("iat 가 없습니다")
	case c.Nonce != nil:
		return "", "", errors.New("nonce 가 있으면 안 됩니다")
	case c.Events[backchannelEvent] == nil:
		return "", "", errors.New("back-channel logout 이벤트가 없습니다")
	case t.Subject == "" && c.Sid == "":
		return "", "", errors.New("sub 와 sid 가 모두 없습니다")
	}
	return t.Subject, c.Sid, nil
}

// ---- 웹훅 ----

func (a *App) webhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20)) // 받은 바이트 그대로 서명을 검증한다
	if err != nil {
		http.Error(w, "bad body", http.StatusBadRequest)
		return
	}
	ts := r.Header.Get("X-Didrakon-Timestamp")
	if !a.validSignature(ts, body, r.Header.Get("X-Didrakon-Signature")) {
		http.Error(w, "bad signature", http.StatusUnauthorized)
		return
	}
	sent, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || abs(time.Now().Unix()-sent) > webhookMaxClockSkew {
		http.Error(w, "stale timestamp", http.StatusUnauthorized)
		return
	}

	delivery := r.Header.Get("X-Didrakon-Delivery")
	a.mu.Lock()
	duplicate := a.deliveries[delivery]
	a.deliveries[delivery] = true
	a.mu.Unlock()
	if duplicate {
		w.Write([]byte(`{"duplicate":true}`))
		return
	}

	var ev struct {
		Type string `json:"type"`
		Data struct {
			SubjectID json.Number `json:"subjectId"`
			Status    string      `json:"status"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &ev); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if ev.Type == "user.status_changed" && ev.Data.Status == "RETIRED" {
		a.retire(ev.Data.SubjectID.String())
	}
	w.Write([]byte(`{"ok":true}`))
}

func (a *App) validSignature(ts string, body []byte, header string) bool {
	got, err := hex.DecodeString(strings.TrimPrefix(header, "sha256="))
	if err != nil || !strings.HasPrefix(header, "sha256=") {
		return false
	}
	mac := hmac.New(sha256.New, a.webhookSecret)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal(mac.Sum(nil), got) // 상수 시간 비교
}

// retire: 퇴사자의 로컬 계정을 끄고 세션을 모두 끝낸다
func (a *App) retire(sub string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, u := range a.users {
		if u.IAMSubjectID == sub {
			u.Active = false
		}
	}
	for id, s := range a.sessions {
		if s.Sub == sub {
			delete(a.sessions, id)
		}
	}
}

// ---- 세션 ----

func (a *App) startSession(w http.ResponseWriter, s *Session) {
	id := randomString()
	a.mu.Lock()
	a.sessions[id] = s
	a.mu.Unlock()
	// 운영(https)에서는 Secure: true
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: id, Path: "/", HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

func (a *App) currentSession(r *http.Request) (string, *Session) {
	c, err := r.Cookie(cookieName)
	if err != nil {
		return "", nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	return c.Value, a.sessions[c.Value]
}

func (a *App) endSession(id string) {
	a.mu.Lock()
	delete(a.sessions, id)
	a.mu.Unlock()
}

// ---- 도우미 ----

func randomString() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func abs(n int64) int64 {
	if n < 0 {
		return -n
	}
	return n
}
