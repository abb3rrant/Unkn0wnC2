package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPeerCredentialHeaderCompatibility(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.RegisterDNSServer("audit-server", "audit.test", "127.0.0.1", "audit-key"); err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer(db, Config{})
	for _, tc := range []struct {
		name, method, query, body, id, key string
		want                               int
	}{
		{name: "headers", method: "GET", id: "audit-server", key: "audit-key", want: 204},
		{name: "headers with matching query identity", method: "GET", query: "?dns_server_id=audit-server", id: "audit-server", key: "audit-key", want: 204},
		{name: "conflicting identity", method: "GET", query: "?dns_server_id=other", id: "audit-server", key: "audit-key", want: 401},
		{name: "invalid header key", method: "GET", id: "audit-server", key: "wrong", want: 401},
		{name: "legacy query", method: "GET", query: "?dns_server_id=audit-server&api_key=audit-key", want: 204},
		{name: "legacy body", method: "POST", body: `{"dns_server_id":"audit-server","api_key":"audit-key"}`, want: 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			handler := api.dnsServerAuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("X-DNS-Server-ID") != "audit-server" {
					t.Error("wrong authenticated identity")
				}
				w.WriteHeader(204)
			}))
			r := httptest.NewRequest(tc.method, "https://audit.invalid/audit-only"+tc.query, strings.NewReader(tc.body))
			r.Header.Set("X-DNS-Server-ID", tc.id)
			r.Header.Set("X-DNS-Server-API-Key", tc.key)
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			if w.Code != tc.want {
				t.Fatalf("status=%d want=%d", w.Code, tc.want)
			}
		})
	}
}

func TestBootstrapTokenHeaderCompatibility(t *testing.T) {
	db := newTestProfileDB(t)
	if err := db.RegisterDNSServer("audit-server", "audit.test", "127.0.0.1", "audit-key"); err != nil {
		t.Fatal(err)
	}
	api := NewAPIServer(db, Config{})
	for _, legacy := range []bool{false, true} {
		token, err := db.IssueHTTPProfileToken("audit-beacon", "audit-profile", "audit-server", `{"audit":"harmless"}`)
		if err != nil {
			t.Fatal(err)
		}
		path := "https://audit.invalid/audit-only"
		r := httptest.NewRequest("GET", path, nil)
		if legacy {
			r = httptest.NewRequest("GET", path+"?dns_server_id=audit-server&api_key=audit-key&token="+token, nil)
		} else {
			r.Header.Set("X-DNS-Server-ID", "audit-server")
			r.Header.Set("X-DNS-Server-API-Key", "audit-key")
			r.Header.Set("X-Bootstrap-Token", token)
		}
		w := httptest.NewRecorder()
		api.dnsServerAuthMiddleware(http.HandlerFunc(api.handleBootstrapProfile)).ServeHTTP(w, r)
		if w.Code != 200 || !strings.Contains(w.Body.String(), "harmless") {
			t.Fatalf("legacy=%v status=%d", legacy, w.Code)
		}
	}
}
