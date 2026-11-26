package main

import (
	"testing"
	"time"
)

// The token model is the only thing standing between an agent and the whole C2,
// so these tests pin the properties that matter: capability mapping fails
// closed, capabilities cannot be widened by a token, and token metadata is read
// back from the database rather than trusted from the JWT.

func TestRequiredCapabilityMapsRoutesFailClosed(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/api/beacons", "beacons:read"},
		{"GET", "/api/beacons/abc123", "beacons:read"},
		{"POST", "/api/beacons/abc123/task", "tasks:write"},
		{"GET", "/api/tasks/T0001/result", "results:read"},
		{"GET", "/api/tasks/T0001/status", "tasks:read"},
		{"POST", "/api/tasks", "tasks:write"},
		{"POST", "/api/builder/builds", "builds:write"},
		{"GET", "/api/builder/builds", "builds:read"},
		{"POST", "/api/listeners", "listeners:write"},
		{"GET", "/api/http-profiles", "listeners:read"},
		{"GET", "/api/logs", "logs:read"},
		{"GET", "/api/exfil/transfers", "exfil:read"},
		{"POST", "/api/operators", "operators:write"},
		{"POST", "/api/tokens", "admin"},
		// unknown route must not fall open
		{"POST", "/api/something-new", "admin"},
	}
	for _, c := range cases {
		if got := requiredCapability(c.method, c.path); got != c.want {
			t.Errorf("%s %s: got %q want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestHasCapabilityCannotWidenScope(t *testing.T) {
	caps := []string{"beacons:read", "tasks:write"}

	if !hasCapability(caps, "beacons:read") {
		t.Error("declared capability must be honoured")
	}
	if hasCapability(caps, "operators:write") {
		t.Error("undeclared capability must be denied")
	}
	if hasCapability(caps, "admin") {
		t.Error("admin must not be implied by other capabilities")
	}
	if !hasCapability([]string{"admin"}, "operators:write") {
		t.Error("admin is a superset")
	}
}

func TestMigration28CreatesEngagementsAndTokenColumns(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	var n int
	if err := db.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='engagements'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatal("engagements table was not created")
	}

	if err := db.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('beacons') WHERE name='engagement_id'`).Scan(&n); err != nil {
		t.Fatalf("query: %v", err)
	}
	if n != 1 {
		t.Fatal("beacons.engagement_id was not added")
	}

	for _, col := range []string{"caps", "egress", "engagement_id", "kind"} {
		var c int
		if err := db.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('sessions') WHERE name=?`, col).Scan(&c); err != nil {
			t.Fatalf("query: %v", err)
		}
		if c != 1 {
			t.Errorf("sessions.%s was not added", col)
		}
	}
}

func TestAPISessionRoundTrip(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	if err := db.CreateOperator("op-1", "tester", "CorrectHorseBattery1!", "admin", "t@example.invalid"); err != nil {
		t.Skipf("operator creation unavailable: %v", err)
	}
	if err := db.CreateEngagement("eng-1", "ADCS Lab", "op-1"); err != nil {
		t.Fatalf("CreateEngagement: %v", err)
	}

	exp := time.Now().Add(time.Hour).Unix()
	caps := []string{"beacons:read", "tasks:write"}
	if err := db.CreateAPISession("sess-1", "op-1", "jti-1", "hash-1", "e2e", caps, "truncated", "eng-1", exp); err != nil {
		t.Fatalf("CreateAPISession: %v", err)
	}

	meta, err := db.GetSessionMeta("jti-1")
	if err != nil {
		t.Fatalf("GetSessionMeta: %v", err)
	}
	if meta.Kind != "mcp" {
		t.Errorf("kind: got %q want mcp", meta.Kind)
	}
	if meta.Egress != "truncated" {
		t.Errorf("egress: got %q want truncated", meta.Egress)
	}
	if meta.EngagementID != "eng-1" {
		t.Errorf("engagement: got %q want eng-1", meta.EngagementID)
	}
	if len(meta.Caps) != 2 || meta.Caps[0] != "beacons:read" {
		t.Errorf("caps round-trip failed: %v", meta.Caps)
	}
	if meta.Revoked {
		t.Error("fresh token must not be revoked")
	}

	// Revocation must be visible on the very next read; the middleware relies on
	// this to kill a leaked token without waiting for JWT expiry.
	if err := db.RevokeSessionByJTI("jti-1"); err != nil {
		t.Fatalf("RevokeSessionByJTI: %v", err)
	}
	meta, err = db.GetSessionMeta("jti-1")
	if err != nil {
		t.Fatalf("GetSessionMeta after revoke: %v", err)
	}
	if !meta.Revoked {
		t.Error("revoked token still reports as live")
	}
}

func TestGetSessionMetaUnknownJTI(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	meta, err := db.GetSessionMeta("does-not-exist")
	if err != nil {
		t.Fatalf("unknown jti must not error: %v", err)
	}
	if meta.Kind != "" || len(meta.Caps) != 0 {
		t.Error("unknown jti must return empty metadata so the middleware rejects it")
	}
}
