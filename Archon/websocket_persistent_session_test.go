package main

import (
	"github.com/golang-jwt/jwt/v5"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestWebSocketRequiresPersistentOwnedSession(t *testing.T) {
	for _, scenario := range []string{"valid", "missing-jti", "missing-row", "wrong-owner", "expired-row", "missing-expiry"} {
		t.Run(scenario, func(t *testing.T) {
			const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
			db := newTestProfileDB(t)
			for _, id := range []string{"audit-user", "other-user"} {
				if err := db.CreateOperator(id, id, "test-password", "viewer", ""); err != nil {
					t.Fatal(err)
				}
			}
			expires := time.Now().Add(time.Hour)
			claims := &Claims{OperatorID: "audit-user", Username: "audit-user", JTI: "audit-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expires)}}
			if scenario == "missing-jti" {
				claims.JTI = ""
			}
			if scenario == "missing-expiry" {
				claims.ExpiresAt = nil
			}
			if scenario != "missing-row" && scenario != "missing-jti" {
				owner := "audit-user"
				if scenario == "wrong-owner" {
					owner = "other-user"
				}
				dbExpiry := expires.Unix()
				if scenario == "expired-row" {
					dbExpiry = time.Now().Add(-time.Hour).Unix()
				}
				if err := db.CreateSession("audit-row", owner, "audit-jti", "audit-hash", "127.0.0.1", "audit", dbExpiry); err != nil {
					t.Fatal(err)
				}
			}
			api := NewAPIServer(db, Config{JWTSecret: secret})
			r := httptest.NewRequest("GET", "http://audit.invalid/ws", nil)
			r.AddCookie(&http.Cookie{Name: "session_token", Value: signedTestToken(t, secret, claims)})
			w := httptest.NewRecorder()
			api.handleWebSocket(w, r)
			want := http.StatusUnauthorized
			// Valid authentication proceeds to upgrade validation; this deliberately
			// non-upgrade request returns 400, without registering a client or socket.
			if scenario == "valid" {
				want = http.StatusBadRequest
			}
			if w.Code != want {
				t.Fatalf("status=%d want=%d", w.Code, want)
			}
		})
	}
}
