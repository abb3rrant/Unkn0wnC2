package main

import (
	"strings"
	"testing"
)

// TestBootstrapTokenIsSingleUse covers the core guarantee: a token hands out its
// payload exactly once, so a token captured off the wire is worthless.
func TestBootstrapTokenIsSingleUse(t *testing.T) {
	db := newTestProfileDB(t)

	payload := `{"mode":"http","listeners":[{"name":"default"}]}`
	token, err := db.IssueHTTPProfileToken("beacon-1", "default", "listener-1", payload)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("token length = %d, want 64 hex chars", len(token))
	}

	got, err := db.ConsumeHTTPProfileToken(token, "beacon-1")
	if err != nil {
		t.Fatalf("first consume: %v", err)
	}
	if got != payload {
		t.Fatalf("payload = %q, want %q", got, payload)
	}

	if _, err := db.ConsumeHTTPProfileToken(token, "beacon-1"); err == nil {
		t.Fatal("second consume succeeded; the token is reusable")
	}
}

// TestBootstrapTokenIsBoundToItsBeacon stops one beacon from redeeming another's
// token, which is what would let a listener enumerate profiles.
func TestBootstrapTokenIsBoundToItsBeacon(t *testing.T) {
	db := newTestProfileDB(t)

	token, err := db.IssueHTTPProfileToken("beacon-1", "default", "listener-1", `{"mode":"http"}`)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}

	if _, err := db.ConsumeHTTPProfileToken(token, "beacon-2"); err == nil {
		t.Fatal("token redeemed by the wrong beacon")
	}
	// The failed attempt must not have spent it.
	if _, err := db.ConsumeHTTPProfileToken(token, "beacon-1"); err != nil {
		t.Fatalf("token unusable after a rejected attempt: %v", err)
	}
}

// TestBootstrapTaskShape pins the short form and its pin, so a later refactor
// cannot silently start shipping the profile inside the task again.
func TestBootstrapTaskShape(t *testing.T) {
	task := buildHTTPProfileTask("http://172.20.0.11:8444/_p", "abc123", "PINVALUE")
	if !strings.HasPrefix(task, "http_profile:") {
		t.Fatalf("task = %q, want the http_profile prefix", task)
	}
	if strings.Contains(task, "listeners") {
		t.Fatalf("task carries a profile: %q", task)
	}
	parts := strings.Split(strings.TrimPrefix(task, "http_profile:"), "|")
	if len(parts) != 3 || parts[2] != "PINVALUE" {
		t.Fatalf("task = %q, want <url>|<token>|<pin>", task)
	}
}
