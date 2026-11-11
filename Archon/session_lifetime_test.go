package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestHTTPAuthRequiresPersistedOwnedLiveSession(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" // gitleaks:allow -- signing key for isolated temporary test fixtures only
	for _, tc := range []struct {
		name         string
		row          bool
		owner        string
		revoked      bool
		rowExpired   bool
		tokenExpired bool
		want         int
	}{
		{"valid", true, "http-user", false, false, false, http.StatusNoContent},
		{"missing", false, "http-user", false, false, false, http.StatusUnauthorized},
		{"wrong-owner", true, "other-user", false, false, false, http.StatusUnauthorized},
		{"revoked", true, "http-user", true, false, false, http.StatusUnauthorized},
		{"expired-row", true, "http-user", false, true, false, http.StatusUnauthorized},
		{"expired-token", true, "http-user", false, false, true, http.StatusUnauthorized},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newTestProfileDB(t)
			for _, id := range []string{"http-user", "other-user"} {
				if err := db.CreateOperator(id, id, "password", "viewer", ""); err != nil {
					t.Fatal(err)
				}
			}
			exp := time.Now().Add(time.Hour)
			if tc.tokenExpired {
				exp = time.Now().Add(-time.Hour)
			}
			claims := &Claims{OperatorID: "http-user", Username: "http-user", Role: "viewer", JTI: "jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(exp)}}
			token := signedTestToken(t, secret, claims)
			if tc.row {
				rowExp := exp.Unix()
				if tc.rowExpired {
					rowExp = time.Now().Add(-time.Hour).Unix()
				}
				if err := db.CreateSession("sid", tc.owner, "jti", "hash", "", "", rowExp); err != nil {
					t.Fatal(err)
				}
				if tc.revoked {
					if err := db.RevokeSessionByJTI("jti"); err != nil {
						t.Fatal(err)
					}
				}
			}
			api := NewAPIServer(db, Config{JWTSecret: secret})
			h := api.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
			r := httptest.NewRequest("GET", "/", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", w.Code, tc.want, w.Body.String())
			}
		})
	}
}

func TestPasswordUpdateRevokesAllOperatorSessions(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.CreateOperator("password-user", "password-user", "old-password", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	for _, jti := range []string{"one", "two"} {
		if err := db.CreateSession("session-"+jti, "password-user", jti, "hash", "", "", time.Now().Add(time.Hour).Unix()); err != nil {
			t.Fatal(err)
		}
	}
	if err := db.UpdateOperatorPassword("password-user", "new-password"); err != nil {
		t.Fatal(err)
	}
	for _, jti := range []string{"one", "two"} {
		revoked, err := db.IsSessionRevoked(jti)
		if err != nil || !revoked {
			t.Fatalf("jti %s revoked=%v err=%v", jti, revoked, err)
		}
	}
	if _, _, err := db.VerifyOperatorCredentials("password-user", "new-password"); err != nil {
		t.Fatalf("new password rejected: %v", err)
	}
}
