package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// Authentication prefers cookies. Header presence alone must not exempt that
// same request from CSRF validation. Use a harmless handler, not a product route.
func TestCSRFMatchesAuthenticationSource(t *testing.T) {
	const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
	db, cleanup := newTestDB(t)
	defer cleanup()
	if err := db.CreateOperator("csrf-user", "csrf-user", "strong-test-password", "viewer", ""); err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer(db, Config{JWTSecret: secret})
	token := signedTestToken(t, secret, &Claims{OperatorID: "csrf-user", Username: "csrf-user", Role: "viewer"})
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		for _, tc := range []struct {
			name   string
			cookie bool
			auth   string
			csrf   string
			want   int
		}{
			{"cookie without csrf", true, "", "", http.StatusForbidden},
			{"cookie with unrelated header", true, "unrelated", "", http.StatusForbidden},
			{"cookie with invalid bearer", true, "Bearer invalid", "", http.StatusForbidden},
			{"cookie with valid bearer", true, "Bearer " + token, "", http.StatusForbidden},
			{"cookie mismatched csrf", true, "Bearer " + token, "mismatch", http.StatusForbidden},
			{"cookie matching csrf", true, "unrelated", "csrf-fixture", http.StatusNoContent},
			{"bearer without cookie", false, "Bearer " + token, "", http.StatusNoContent},
			{"invalid bearer without cookie", false, "Bearer invalid", "", http.StatusUnauthorized},
		} {
			t.Run(method+"/"+tc.name, func(t *testing.T) {
				called := false
				handler := api.authMiddleware(api.csrfMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true; w.WriteHeader(http.StatusNoContent) })))
				r := httptest.NewRequest(method, "https://archon.example/test-only", nil)
				if tc.cookie {
					r.AddCookie(&http.Cookie{Name: "session_token", Value: token})
				}
				r.Header.Set("Authorization", tc.auth)
				if tc.csrf != "" {
					r.AddCookie(&http.Cookie{Name: "csrf_token", Value: "csrf-fixture"})
					r.Header.Set("X-CSRF-Token", tc.csrf)
				}
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, r)
				if w.Code != tc.want || called != (tc.want == http.StatusNoContent) {
					t.Fatalf("status=%d called=%v, want status=%d; body=%s", w.Code, called, tc.want, w.Body.String())
				}
			})
		}
	}
}
