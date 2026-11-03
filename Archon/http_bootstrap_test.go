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

	// A few redemptions are allowed so a dropped response does not lose the update,
	// but the allowance is finite.
	for i := 2; i <= HTTPProfileTokenUses; i++ {
		if _, err := db.ConsumeHTTPProfileToken(token, "beacon-1"); err != nil {
			t.Fatalf("redemption %d failed: %v", i, err)
		}
	}
	if _, err := db.ConsumeHTTPProfileToken(token, "beacon-1"); err == nil {
		t.Fatalf("token survived %d redemptions; the allowance is not enforced", HTTPProfileTokenUses)
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

// TestServerServingHTTPProfile covers the guard that keeps an operator from
// applying a profile no listener serves: the bootstrap URL would 404 and the
// beacon would spend its token on nothing.
func TestServerServingHTTPProfile(t *testing.T) {
	db := newTestProfileDB(t)

	if _, ok := db.ServerServingHTTPProfile("default"); ok {
		t.Fatal("unassigned profile reported as served")
	}
	if err := db.AssignHTTPProfile("dns-server-A", "default"); err != nil {
		t.Fatalf("assign: %v", err)
	}
	serverID, ok := db.ServerServingHTTPProfile("default")
	if !ok || serverID != "dns-server-A" {
		t.Fatalf("ServerServingHTTPProfile = (%q,%v), want (dns-server-A,true)", serverID, ok)
	}
}

// TestBeaconTransportPendingUntilConfirmed covers the honesty problem: recording a
// transport at queue time is not the same as the beacon applying it.
func TestBeaconTransportPendingUntilConfirmed(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-pending"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	if db.BeaconTransportPending("beacon-pending") {
		t.Fatal("a beacon with no recorded change is already pending")
	}

	if err := db.SetBeaconHTTPListeners("beacon-pending", []string{"default"}, "dual"); err != nil {
		t.Fatalf("record transport: %v", err)
	}
	if !db.BeaconTransportPending("beacon-pending") {
		t.Fatal("requested transport is not marked pending")
	}

	// A dual beacon reports whichever path the event used, so either path confirms.
	if err := db.ConfirmBeaconTransport("beacon-pending", "dns"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if db.BeaconTransportPending("beacon-pending") {
		t.Fatal("a DNS report did not confirm a pending dual change")
	}

	// An HTTP request is the only thing that confirms an http-only change.
	if err := db.SetBeaconHTTPListeners("beacon-pending", []string{"default"}, "http"); err != nil {
		t.Fatalf("record transport: %v", err)
	}
	if err := db.ConfirmBeaconTransport("beacon-pending", "dns"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if !db.BeaconTransportPending("beacon-pending") {
		t.Fatal("a DNS report cleared a pending http-only change")
	}
	if err := db.ConfirmBeaconTransport("beacon-pending", "http"); err != nil {
		t.Fatalf("confirm: %v", err)
	}
	if db.BeaconTransportPending("beacon-pending") {
		t.Fatal("pending marker survived a matching report")
	}
}
