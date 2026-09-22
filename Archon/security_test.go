package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

func TestLoadConfigAppliesEnvironmentWithoutConfigFile(t *testing.T) {
	t.Setenv("MASTER_JWT_SECRET", "0123456789abcdef0123456789abcdef") //gitleaks:allow -- deterministic test fixture
	t.Setenv("MASTER_ADMIN_PASSWORD", "a-strong-test-password")
	t.Setenv("MASTER_ENCRYPTION_KEY", "0123456789abcdef0123456789abcdef") //gitleaks:allow -- deterministic test fixture

	cfg, err := LoadConfig(filepath.Join(t.TempDir(), "missing.json"))
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if cfg.JWTSecret != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("JWTSecret = %q, want environment override", cfg.JWTSecret)
	}
	if cfg.AdminCredentials.Password != "a-strong-test-password" {
		t.Fatalf("admin password was not loaded from the environment")
	}
	if cfg.EncryptionKey != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("EncryptionKey = %q, want environment override", cfg.EncryptionKey)
	}
}

func TestValidateConfigRejectsExampleCredentials(t *testing.T) {
	base := DefaultConfig()
	base.JWTSecret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	base.AdminCredentials.Password = "a-strong-test-password"
	base.EncryptionKey = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture

	for _, tc := range []struct {
		name string
		edit func(*Config)
		want string
	}{
		{
			name: "example admin password",
			edit: func(cfg *Config) { cfg.AdminCredentials.Password = "CHANGE_ME_ON_FIRST_LOGIN" },
			want: "example/weak admin password",
		},
		{
			name: "example encryption key",
			edit: func(cfg *Config) { cfg.EncryptionKey = "CHANGE_ME_GENERATED_WITH_OPENSSL_RAND_HEX_16" },
			want: "example/weak encryption key",
		},
		{
			name: "compose admin password",
			edit: func(cfg *Config) { cfg.AdminCredentials.Password = "TestAdmin2026!" },
			want: "example/weak admin password",
		},
		{
			name: "compose encryption key",
			edit: func(cfg *Config) { cfg.EncryptionKey = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6" }, //gitleaks:allow -- known rejected sentinel
			want: "example/weak encryption key",
		},
		{
			name: "compose jwt secret",
			edit: func(cfg *Config) { cfg.JWTSecret = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" }, //gitleaks:allow -- known rejected sentinel
			want: "example/weak jwt secret",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := base
			tc.edit(&cfg)
			err := ValidateConfig(cfg)
			if err == nil || !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Fatalf("ValidateConfig() error = %v, want message containing %q", err, tc.want)
			}
		})
	}
}

func TestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	api := NewAPIServer(nil, Config{})
	r := httptest.NewRequest(http.MethodGet, "https://archon.example/api/stats", nil)
	r.RemoteAddr = "198.51.100.20:4242"
	r.Header.Set("X-Forwarded-For", "203.0.113.99")
	r.Header.Set("X-Real-IP", "203.0.113.98")

	if got := api.clientIP(r); got != "198.51.100.20" {
		t.Fatalf("clientIP() = %q, want socket peer", got)
	}
}

func TestClientIPWalksForwardedChainFromTrustedProxy(t *testing.T) {
	api := NewAPIServer(nil, Config{TrustedProxyCIDRs: []string{"10.0.0.0/8", "192.0.2.0/24"}})
	r := httptest.NewRequest(http.MethodGet, "https://archon.example/api/stats", nil)
	r.RemoteAddr = "10.0.0.4:4242"
	// A client supplied a spoofed leftmost value; the trusted proxy appended the
	// actual peer. Walking from the right must stop at the first untrusted hop.
	r.Header.Set("X-Forwarded-For", "203.0.113.99, 198.51.100.7, 192.0.2.8")

	if got := api.clientIP(r); got != "198.51.100.7" {
		t.Fatalf("clientIP() = %q, want first untrusted hop", got)
	}
}

func TestRequireRolesRejectsViewerBeforeHandler(t *testing.T) {
	called := false
	handler := requireRoles("admin", "operator")(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		called = true
	}))
	r := httptest.NewRequest(http.MethodPost, "https://archon.example/api/beacons/b1/task", nil)
	r.Header.Set("X-Operator-Role", "viewer")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusForbidden)
	}
	if called {
		t.Fatal("protected handler was called for viewer")
	}
}

func TestRequireRolesAllowsOperator(t *testing.T) {
	called := false
	handler := requireRoles("admin", "operator")(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodPost, "https://archon.example/api/beacons/b1/task", nil)
	r.Header.Set("X-Operator-Role", "operator")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, r)
	if w.Code != http.StatusNoContent || !called {
		t.Fatalf("status = %d, called = %v; want 204 and called", w.Code, called)
	}
}

func TestDNSServerRegistrationRequiresPreprovisionedCredentials(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()
	api := NewAPIServer(db, Config{})
	router := mux.NewRouter()
	api.SetupRoutes(router)

	registration := `{"server_id":"unknown-server","domain":"new.example.test","address":"127.0.0.1","api_key":"attacker-chosen-key"}`
	req := httptest.NewRequest(http.MethodPost, "/api/dns-server/register", strings.NewReader(registration))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("unknown DNS server registration status = %d, want %d; body=%s", rec.Code, http.StatusUnauthorized, rec.Body.String())
	}

	const serverID = "provisioned-server"
	const apiKey = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	if err := db.RegisterDNSServer(serverID, "old.example.test", "127.0.0.1", apiKey); err != nil {
		t.Fatalf("preprovision DNS server: %v", err)
	}
	registration = `{"server_id":"provisioned-server","domain":"new.example.test","address":"127.0.0.2","api_key":"0123456789abcdef0123456789abcdef"}` //gitleaks:allow -- deterministic test fixture
	req = httptest.NewRequest(http.MethodPost, "/api/dns-server/register", strings.NewReader(registration))
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("preprovisioned DNS server registration status = %d, want %d; body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestAPIRejectsOversizedRequestBody(t *testing.T) {
	api := NewAPIServer(nil, Config{})
	router := mux.NewRouter()
	api.SetupRoutes(router)

	body := strings.NewReader(strings.Repeat("x", maxAPIRequestBodyBytes+1))
	r := httptest.NewRequest(http.MethodPost, "/api/auth/login", body)
	r.RemoteAddr = "198.51.100.20:4242"
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %q; want 413", w.Code, w.Body.String())
	}
}

func TestArchonHTTPServerHasHeaderResourceLimits(t *testing.T) {
	srv := newArchonHTTPServer("127.0.0.1:0", http.NewServeMux())
	if srv.ReadHeaderTimeout < 5*time.Second {
		t.Fatalf("ReadHeaderTimeout = %v, want at least 5s", srv.ReadHeaderTimeout)
	}
	if srv.MaxHeaderBytes <= 0 || srv.MaxHeaderBytes > 1<<20 {
		t.Fatalf("MaxHeaderBytes = %d, want a positive value no larger than 1 MiB", srv.MaxHeaderBytes)
	}
}

func TestLogoutDeletionCookiesKeepSecurityAttributes(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()
	api := NewAPIServer(db, Config{})
	r := httptest.NewRequest(http.MethodPost, "https://archon.example/api/auth/logout", nil)
	r.Header.Set("X-Operator-ID", "viewer-1")
	r.Header.Set("X-Operator-Username", "viewer")
	w := httptest.NewRecorder()

	api.handleLogout(w, r)
	cookies := w.Result().Cookies()
	if len(cookies) != 2 {
		t.Fatalf("deletion cookies = %d, want 2", len(cookies))
	}
	for _, cookie := range cookies {
		if !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
			t.Errorf("cookie %q attributes: Secure=%v SameSite=%v", cookie.Name, cookie.Secure, cookie.SameSite)
		}
		if cookie.Name == "session_token" && !cookie.HttpOnly {
			t.Errorf("session deletion cookie must remain HttpOnly")
		}
	}
}

func signedTestToken(t *testing.T, secret string, claims *Claims) string {
	t.Helper()
	token, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return token
}

func TestAuthMiddlewareUsesCurrentOperatorRole(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	db, cleanup := newTestDB(t)
	defer cleanup()
	if err := db.CreateOperator("operator-1", "alice", "strong-password", "viewer", ""); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	api := NewAPIServer(db, Config{JWTSecret: secret})
	token := signedTestToken(t, secret, &Claims{OperatorID: "operator-1", Username: "alice", Role: "admin"})

	var gotRole string
	handler := api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRole = r.Header.Get("X-Operator-Role")
		w.WriteHeader(http.StatusNoContent)
	}))
	r := httptest.NewRequest(http.MethodGet, "https://archon.example/api/stats", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("status = %d, body = %q", w.Code, w.Body.String())
	}
	if gotRole != "viewer" {
		t.Fatalf("effective role = %q, want current database role viewer", gotRole)
	}
}

func TestAuthMiddlewareRejectsDisabledOperatorSession(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	db, cleanup := newTestDB(t)
	defer cleanup()
	if err := db.CreateOperator("operator-1", "alice", "strong-password", "operator", ""); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	if err := db.SetOperatorActive("operator-1", false); err != nil {
		t.Fatalf("SetOperatorActive: %v", err)
	}
	api := NewAPIServer(db, Config{JWTSecret: secret})
	token := signedTestToken(t, secret, &Claims{OperatorID: "operator-1", Username: "alice", Role: "operator"})

	called := false
	handler := api.authMiddleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	r := httptest.NewRequest(http.MethodGet, "https://archon.example/api/stats", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)

	if w.Code != http.StatusUnauthorized || called {
		t.Fatalf("status = %d, called = %v; want 401 and not called", w.Code, called)
	}
}

func TestViewerCannotMutateOperationalRoutes(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	db, cleanup := newTestDB(t)
	defer cleanup()
	if err := db.CreateOperator("viewer-1", "viewer", "strong-password", "viewer", ""); err != nil {
		t.Fatalf("CreateOperator: %v", err)
	}
	api := NewAPIServer(db, Config{JWTSecret: secret})
	router := mux.NewRouter()
	api.SetupRoutes(router)

	token := signedTestToken(t, secret, &Claims{
		OperatorID: "viewer-1",
		Username:   "viewer",
		Role:       "viewer",
	})

	cases := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodDelete, "/api/dns-servers/d1", ""},
		{http.MethodPut, "/api/beacons/b1/domains", `{}`},
		{http.MethodPost, "/api/beacons/b1/task", `{}`},
		{http.MethodDelete, "/api/beacons/b1", ""},
		{http.MethodPost, "/api/builder/client", `{}`},
		{http.MethodPost, "/api/http/profiles", `{}`},
		{http.MethodPost, "/api/http/transport", `{}`},
		{http.MethodPost, "/api/listeners/d1/http-profiles", `{}`},
		{http.MethodPost, "/api/beacons/bulk/task", `{}`},
	}
	for _, tc := range cases {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.path, strings.NewReader(tc.body))
			r.RemoteAddr = "198.51.100.20:4242"
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			if w.Code != http.StatusForbidden {
				t.Fatalf("status = %d, body = %q; want 403", w.Code, w.Body.String())
			}
		})
	}
}

func TestWebSocketOriginRequiresExactHost(t *testing.T) {
	for _, tc := range []struct {
		name   string
		origin string
		want   bool
	}{
		{name: "same origin", origin: "https://archon.example:8443", want: true},
		{name: "host as attacker subdomain", origin: "https://archon.example:8443.attacker.test", want: false},
		{name: "host in attacker query", origin: "https://attacker.test/?archon.example:8443", want: false},
		{name: "missing origin", origin: "", want: false},
		{name: "malformed origin", origin: "://bad", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "https://archon.example:8443/ws", nil)
			r.Host = "archon.example:8443"
			if tc.origin != "" {
				r.Header.Set("Origin", tc.origin)
			}
			if got := websocketOriginAllowed(r); got != tc.want {
				t.Fatalf("websocketOriginAllowed() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestDownloadDispositionCannotInjectHeaders(t *testing.T) {
	disposition, safeName := downloadDisposition("artifact\"\r\nX-Injected: yes.txt")
	if strings.ContainsAny(disposition, "\r\n") || strings.ContainsAny(safeName, "\r\n") {
		t.Fatalf("unsafe download metadata: disposition=%q name=%q", disposition, safeName)
	}
	if !strings.HasPrefix(disposition, "attachment;") {
		t.Fatalf("Content-Disposition = %q, want attachment", disposition)
	}
}

func TestJSONAndSensitivePagesDisableCaching(t *testing.T) {
	api := &APIServer{}
	jsonRecorder := httptest.NewRecorder()
	api.sendJSON(jsonRecorder, map[string]bool{"ok": true})
	if got := jsonRecorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("JSON Cache-Control = %q, want no-store", got)
	}

	webRoot := t.TempDir()
	for _, name := range []string{"logs.html", "report.html"} {
		if err := os.WriteFile(filepath.Join(webRoot, name), []byte("test"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	api.config.WebRoot = webRoot
	for name, handler := range map[string]http.HandlerFunc{
		"logs": api.handleLogsPage, "report": api.handleReportPage,
	} {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, "/"+name, nil))
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Errorf("%s Cache-Control = %q, want no-store", name, got)
		}
	}
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	handler := securityHeadersMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/dashboard", nil))

	for header, want := range map[string]string{
		"X-Frame-Options":        "DENY",
		"X-Content-Type-Options": "nosniff",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := recorder.Header().Get(header); got != want {
			t.Errorf("%s = %q, want %q", header, got, want)
		}
	}
	if csp := recorder.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'none'") {
		t.Fatalf("Content-Security-Policy lacks frame-ancestors: %q", csp)
	}
}

func TestLogFileMetadataDoesNotExposeAbsolutePath(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "archon.log"), []byte("test"), 0600); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	metadata, err := logFileMetadata(entries[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := metadata["path"]; exists {
		t.Fatalf("log metadata exposed filesystem path: %#v", metadata)
	}
}
