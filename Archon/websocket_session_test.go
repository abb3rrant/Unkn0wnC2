package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/websocket"
)

// Exercise the actual upgrade and write pump using only a harmless local event.
func TestWebSocketSessionAuthorizationLifetime(t *testing.T) {
	for _, scenario := range []string{"active", "disable", "revoke", "expire", "disable-idle", "revoke-idle", "expire-idle", "delete", "external-revoke", "db-expire", "wrong-owner"} {
		t.Run(scenario, func(t *testing.T) {
			action := strings.TrimSuffix(scenario, "-idle")
			idle := strings.HasSuffix(scenario, "-idle")
			const secret = "0123456789abcdef0123456789abcdef" //gitleaks:allow -- deterministic test fixture
			db := newTestProfileDB(t)
			if err := db.CreateOperator("ws-auth-user", "ws-auth-user", "test-password", "viewer", ""); err != nil {
				t.Fatal(err)
			}
			expiry := time.Now().Add(time.Hour)
			if action == "expire" {
				expiry = time.Now().Add(2 * time.Second).Truncate(time.Second)
			}
			token := signedTestToken(t, secret, &Claims{OperatorID: "ws-auth-user", Username: "ws-auth-user", Role: "viewer", JTI: "ws-auth-jti", RegisteredClaims: jwt.RegisteredClaims{ExpiresAt: jwt.NewNumericDate(expiry)}})
			if err := db.CreateSession("ws-auth-session", "ws-auth-user", "ws-auth-jti", "test-hash", "127.0.0.1", "test", expiry.Unix()); err != nil {
				t.Fatal(err)
			}
			api := NewAPIServer(db, Config{JWTSecret: secret})
			hub := NewWebSocketHub()
			previous := wsHub
			wsHub = hub
			ready := make(chan *WebSocketClient, 1)
			stopped := make(chan struct{})
			go func() { client := <-hub.register; ready <- client; <-hub.unregister; close(stopped) }()
			server := httptest.NewServer(http.HandlerFunc(api.handleWebSocket))
			headers := http.Header{"Origin": []string{server.URL}, "Cookie": []string{"session_token=" + token}}
			conn, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(server.URL, "http"), headers)
			if err != nil {
				server.Close()
				wsHub = previous
				t.Fatal(err)
			}
			defer func() {
				conn.Close()
				server.Close()
				select {
				case <-stopped:
				case <-time.After(2 * time.Second):
					t.Error("WebSocket pumps did not unregister")
				}
				wsHub = previous
			}()
			client := <-ready
			switch action {
			case "disable":
				if err := db.SetOperatorActive("ws-auth-user", false); err != nil {
					t.Fatal(err)
				}
			case "revoke":
				if err := db.RevokeSessionByJTI("ws-auth-jti"); err != nil {
					t.Fatal(err)
				}
			case "expire":
				time.Sleep(time.Until(expiry) + 20*time.Millisecond)
			case "delete":
				if _, err := db.db.Exec(`DELETE FROM sessions WHERE jti = ?`, "ws-auth-jti"); err != nil {
					t.Fatal(err)
				}
			case "external-revoke":
				// Use another database handle so the in-process cache is not invalidated.
				var seq int
				var name, path string
				if err := db.db.QueryRow(`PRAGMA database_list`).Scan(&seq, &name, &path); err != nil {
					t.Fatal(err)
				}
				other, err := sql.Open("sqlite", path)
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				if _, err := other.Exec(`UPDATE sessions SET is_revoked = 1 WHERE jti = ?`, "ws-auth-jti"); err != nil {
					t.Fatal(err)
				}
			case "db-expire":
				if _, err := db.db.Exec(`UPDATE sessions SET expires_at = ? WHERE jti = ?`, time.Now().Add(-time.Hour).Unix(), "ws-auth-jti"); err != nil {
					t.Fatal(err)
				}
			case "wrong-owner":
				if err := db.CreateOperator("other-user", "other-user", "test-password", "viewer", ""); err != nil {
					t.Fatal(err)
				}
				if _, err := db.db.Exec(`UPDATE sessions SET operator_id = ? WHERE jti = ?`, "other-user", "ws-auth-jti"); err != nil {
					t.Fatal(err)
				}
			}
			if !idle {
				client.send <- []byte(`{"type":"audit_only","marker":"harmless"}`)
			}
			conn.SetReadDeadline(time.Now().Add(7 * time.Second))
			_, body, err := conn.ReadMessage()
			if action == "active" {
				if err != nil || !strings.Contains(string(body), "harmless") {
					t.Fatalf("active session failed: body=%q err=%v", body, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("unauthorized session received event after %s: %s", action, body)
			}
			if !websocket.IsCloseError(err, websocket.ClosePolicyViolation) {
				t.Fatalf("expected policy close after %s, got %v", action, err)
			}
		})
	}
}
