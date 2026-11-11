package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/mux"
)

type loginFixture struct {
	token, csrf string
	claims      *Claims
}

func loginThroughRouter(t *testing.T, router http.Handler, username, password, ip, secret string, want int) loginFixture {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	req := httptest.NewRequest("POST", "https://fixture.invalid/api/auth/login", bytes.NewReader(body))
	req.RemoteAddr = ip + ":1234"
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != want {
		t.Fatalf("login status=%d want=%d", rec.Code, want)
	}
	result := loginFixture{}
	if want != http.StatusOK {
		return result
	}
	for _, cookie := range rec.Result().Cookies() {
		if cookie.Name == "session_token" {
			result.token = cookie.Value
		}
		if cookie.Name == "csrf_token" {
			result.csrf = cookie.Value
		}
	}
	if result.token == "" || result.csrf == "" {
		t.Fatal("login did not issue both cookies")
	}
	claims := &Claims{}
	if _, err := jwt.ParseWithClaims(result.token, claims, func(*jwt.Token) (interface{}, error) { return []byte(secret), nil }); err != nil {
		t.Fatal(err)
	}
	result.claims = claims
	return result
}

func fixtureAuthedRequest(router http.Handler, session loginFixture, method, path string, body interface{}) int {
	encoded, _ := json.Marshal(body)
	req := httptest.NewRequest(method, "https://fixture.invalid"+path, bytes.NewReader(encoded))
	req.RemoteAddr = "127.0.0.20:1234"
	req.AddCookie(&http.Cookie{Name: "session_token", Value: session.token})
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: session.csrf})
	req.Header.Set("X-CSRF-Token", session.csrf)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec.Code
}

func TestPasswordChangeHandlerRevokesOnlyTargetSessions(t *testing.T) {
	const secret = "local-password-reset-fixture-secret"
	for _, scenario := range []string{"self-change", "admin-reset"} {
		t.Run(scenario, func(t *testing.T) {
			db := newTestProfileDB(t)
			for _, account := range []struct{ id, role string }{{"target", "viewer"}, {"admin", "admin"}, {"other", "viewer"}} {
				if err := db.CreateOperator(account.id, account.id, "fixture-before", account.role, ""); err != nil {
					t.Fatal(err)
				}
			}
			api := NewAPIServer(db, Config{JWTSecret: secret, SessionTimeout: 60})
			router := mux.NewRouter()
			api.SetupRoutes(router)
			target1 := loginThroughRouter(t, router, "target", "fixture-before", "127.0.0.2", secret, http.StatusOK)
			target2 := loginThroughRouter(t, router, "target", "fixture-before", "127.0.0.2", secret, http.StatusOK)
			admin := loginThroughRouter(t, router, "admin", "fixture-before", "127.0.0.3", secret, http.StatusOK)
			other := loginThroughRouter(t, router, "other", "fixture-before", "127.0.0.4", secret, http.StatusOK)
			// Prime the legacy cache: HTTP/WS must still observe the committed
			// revocation rather than a cached false result.
			for _, s := range []loginFixture{target1, target2} {
				if revoked, err := db.IsSessionRevoked(s.claims.JTI); err != nil || revoked {
					t.Fatal("fixture session not live")
				}
			}
			actor := target1
			payload := map[string]string{"current_password": "fixture-before", "new_password": "fixture-after"}
			if scenario == "admin-reset" {
				actor = admin
				delete(payload, "current_password")
			} else {
				bad := map[string]string{"current_password": "wrong-fixture", "new_password": "fixture-after"}
				if got := fixtureAuthedRequest(router, actor, "POST", "/api/operators/target/password", bad); got != http.StatusUnauthorized {
					t.Fatalf("wrong password status=%d", got)
				}
				if got := fixtureAuthedRequest(router, target1, "GET", "/api/auth/me", nil); got != http.StatusOK {
					t.Fatal("failed password change revoked the session")
				}
			}
			if got := fixtureAuthedRequest(router, actor, "POST", "/api/operators/target/password", payload); got != http.StatusOK {
				t.Fatalf("password update status=%d", got)
			}
			for _, session := range []loginFixture{target1, target2} {
				if got := fixtureAuthedRequest(router, session, "GET", "/api/auth/me", nil); got != http.StatusUnauthorized {
					t.Fatalf("old HTTP session status=%d", got)
				}
				if api.websocketSessionAuthorized(session.claims) {
					t.Fatal("old WS session survived password update")
				}
			}
			for _, session := range []loginFixture{admin, other} {
				if got := fixtureAuthedRequest(router, session, "GET", "/api/auth/me", nil); got != http.StatusOK {
					t.Fatalf("unrelated account session status=%d", got)
				}
			}
			loginThroughRouter(t, router, "target", "fixture-before", "127.0.0.2", secret, http.StatusUnauthorized)
			fresh := loginThroughRouter(t, router, "target", "fixture-after", "127.0.0.2", secret, http.StatusOK)
			if got := fixtureAuthedRequest(router, fresh, "GET", "/api/auth/me", nil); got != http.StatusOK {
				t.Fatalf("fresh session rejected: %d", got)
			}
		})
	}
}

func TestPasswordRevocationFailureRollsBackPasswordHash(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("target", "target", "fixture-before", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	if err := db.CreateSession("sid", "target", "jti", "fixture-hash", "", "", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, err := db.db.Exec(`CREATE TRIGGER fail_revoke BEFORE UPDATE OF is_revoked ON sessions BEGIN SELECT RAISE(ABORT,'fixture revocation failure'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.UpdateOperatorPassword("target", "fixture-after"); err == nil {
		t.Fatal("revocation failure reported success")
	}
	if _, _, err := db.VerifyOperatorCredentials("target", "fixture-before"); err != nil {
		t.Fatal("old password did not survive rollback")
	}
	if _, _, err := db.VerifyOperatorCredentials("target", "fixture-after"); err == nil {
		t.Fatal("new password escaped rollback")
	}
	var revoked bool
	if err := db.db.QueryRow(`SELECT is_revoked FROM sessions WHERE jti='jti'`).Scan(&revoked); err != nil || revoked {
		t.Fatal("original session unexpectedly revoked")
	}
}

func TestHTTPAuthRejectsMissingClaimAndRemovedSession(t *testing.T) {
	const secret = "local-claim-fixture-secret"
	for _, scenario := range []string{"missing-jti", "missing-expiry", "deleted-row", "external-revoke-after-cache"} {
		t.Run(scenario, func(t *testing.T) {
			db := newTestProfileDB(t)
			if err := db.CreateOperator("fixture", "fixture", "fixture-password", "viewer", ""); err != nil {
				t.Fatal(err)
			}
			claims := &Claims{OperatorID: "fixture", JTI: "fixture-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour))}}
			if err := db.CreateSession("fixture-row", "fixture", claims.JTI, "fixture-hash", "", "", claims.ExpiresAt.Unix()); err != nil {
				t.Fatal(err)
			}
			if _, err := db.IsSessionRevoked(claims.JTI); err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "missing-jti":
				claims.JTI = ""
			case "missing-expiry":
				claims.ExpiresAt = nil
			case "deleted-row":
				if _, err := db.db.Exec(`DELETE FROM sessions WHERE jti=?`, claims.JTI); err != nil {
					t.Fatal(err)
				}
			case "external-revoke-after-cache":
				if _, err := db.db.Exec(`UPDATE sessions SET is_revoked=1 WHERE jti=?`, claims.JTI); err != nil {
					t.Fatal(err)
				}
			}
			api := NewAPIServer(db, Config{JWTSecret: secret})
			req := httptest.NewRequest("GET", "/api/auth/me", nil)
			req.Header.Set("Authorization", "Bearer "+signedTestToken(t, secret, claims))
			rec := httptest.NewRecorder()
			api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) })).ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("invalid session accepted: %d", rec.Code)
			}
		})
	}
}
