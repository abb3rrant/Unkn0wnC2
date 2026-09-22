package main

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newAssignmentTestDB creates a migrated database in a temp file.
func newAssignmentTestDB(t *testing.T) *MasterDatabase {
	t.Helper()

	path := filepath.Join(t.TempDir(), "assignments-test.db")
	db, err := NewMasterDatabase(path)
	if err != nil {
		t.Fatalf("NewMasterDatabase() error = %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// seedProfile stores a valid profile so assignments have something to point at.
func seedProfile(t *testing.T, db *MasterDatabase, name string) {
	t.Helper()

	stored, err := normalizeHTTPProfileDocument(name, `{
		"scheme": "http",
		"bind_port": 8080,
		"beacon_host": "10.0.0.5:8080",
		"uris": {
			"register": ["/api/v1/ping"],
			"task": ["/api/v1/sync"],
			"result": ["/api/v1/report"],
			"ack": ["/api/v1/ack"]
		}
	}`)
	if err != nil {
		t.Fatalf("failed to build a seed profile: %v", err)
	}
	if err := db.SaveHTTPProfile(name, stored); err != nil {
		t.Fatalf("failed to seed profile %q: %v", name, err)
	}
}

// TestHTTPProfileAssignments_RoundTrip covers attach, list, deliver and detach.
func TestHTTPProfileAssignments_RoundTrip(t *testing.T) {
	db := newAssignmentTestDB(t)

	if err := createTestBeacon(db, "beacon-1"); err != nil {
		t.Fatal(err)
	}
	seedProfile(t, db, "cdn-assets")
	seedProfile(t, db, "edge")

	if err := db.AssignHTTPProfile("dns1", "cdn-assets"); err != nil {
		t.Fatalf("AssignHTTPProfile() error = %v", err)
	}
	if err := db.AssignHTTPProfile("dns1", "edge"); err != nil {
		t.Fatal(err)
	}

	names, err := db.GetAssignedHTTPProfileNames("dns1")
	if err != nil {
		t.Fatalf("GetAssignedHTTPProfileNames() error = %v", err)
	}
	if len(names) != 2 || names[0] != "cdn-assets" || names[1] != "edge" {
		t.Fatalf("assigned = %v, want [cdn-assets edge]", names)
	}

	// Assigning the same profile twice must not error or duplicate.
	if err := db.AssignHTTPProfile("dns1", "cdn-assets"); err != nil {
		t.Fatalf("re-assigning returned an error: %v", err)
	}
	names, _ = db.GetAssignedHTTPProfileNames("dns1")
	if len(names) != 2 {
		t.Fatalf("re-assigning changed the set: %v", names)
	}

	// Delivery carries the document, which is what the server applies.
	assigned, err := db.GetAssignedHTTPProfiles("dns1")
	if err != nil {
		t.Fatalf("GetAssignedHTTPProfiles() error = %v", err)
	}
	if len(assigned) != 2 {
		t.Fatalf("delivered %d profiles, want 2", len(assigned))
	}
	if assigned[0].Name != "cdn-assets" {
		t.Errorf("first assignment = %q, want cdn-assets", assigned[0].Name)
	}
	if assigned[0].Revision == 0 {
		t.Error("revision was not set, so a server cannot tell versions apart")
	}
	if !strings.Contains(string(assigned[0].Document), "/api/v1/sync") {
		t.Errorf("document lost its contents: %s", assigned[0].Document)
	}

	// A different server gets only its own assignments.
	other, err := db.GetAssignedHTTPProfiles("dns2")
	if err != nil {
		t.Fatal(err)
	}
	if len(other) != 0 {
		t.Fatalf("dns2 received %d profiles assigned to dns1", len(other))
	}

	// Detach.
	if err := db.UnassignHTTPProfile("dns1", "edge"); err != nil {
		t.Fatalf("UnassignHTTPProfile() error = %v", err)
	}
	names, _ = db.GetAssignedHTTPProfileNames("dns1")
	if len(names) != 1 || names[0] != "cdn-assets" {
		t.Fatalf("after detach assigned = %v, want [cdn-assets]", names)
	}
}

// TestHTTPProfileAssignments_DeletedProfileIsSkipped asserts deleting a profile while it
// is assigned does not break delivery for the others.
func TestHTTPProfileAssignments_DeletedProfileIsSkipped(t *testing.T) {
	db := newAssignmentTestDB(t)

	seedProfile(t, db, "cdn-assets")
	seedProfile(t, db, "doomed")

	if err := db.AssignHTTPProfile("dns1", "cdn-assets"); err != nil {
		t.Fatal(err)
	}
	if err := db.AssignHTTPProfile("dns1", "doomed"); err != nil {
		t.Fatal(err)
	}
	if err := db.DeleteHTTPProfile("doomed"); err != nil {
		t.Fatal(err)
	}

	assigned, err := db.GetAssignedHTTPProfiles("dns1")
	if err != nil {
		t.Fatalf("GetAssignedHTTPProfiles() error = %v", err)
	}
	if len(assigned) != 1 || assigned[0].Name != "cdn-assets" {
		t.Fatalf("delivered = %+v, want only cdn-assets", assigned)
	}

	// The assignment row survives, so re-creating the profile restores delivery.
	seedProfile(t, db, "doomed")
	assigned, err = db.GetAssignedHTTPProfiles("dns1")
	if err != nil {
		t.Fatal(err)
	}
	if len(assigned) != 2 {
		t.Fatalf("after re-creating the profile, delivered %d, want 2", len(assigned))
	}
}

// seedDNSServer inserts a DNS server row so the reported-state column has a row to
// write to. The tests build databases directly rather than through the registration
// endpoint, so nothing else creates one.
func seedDNSServer(t *testing.T, db *MasterDatabase, id string) {
	t.Helper()

	now := time.Now().Unix()
	if _, err := db.db.Exec(`
		INSERT INTO dns_servers (id, domain, address, api_key_hash, status, first_seen, last_checkin, created_at, updated_at)
		VALUES (?, ?, ?, ?, 'active', ?, ?, ?, ?)
	`, id, id+".example.com", "127.0.0.1", "hash", now, now, now, now); err != nil {
		t.Fatalf("failed to seed DNS server %q: %v", id, err)
	}
}

// TestDNSServerHTTPListeners_RoundTrip asserts the reported state survives storage and
// that a malformed report degrades to "nothing reported" rather than an error.
func TestDNSServerHTTPListeners_RoundTrip(t *testing.T) {
	db := newAssignmentTestDB(t)
	seedDNSServer(t, db, "dns1")

	servers, err := db.GetDNSServers()
	if err != nil {
		t.Fatal(err)
	}
	if len(servers) != 1 {
		t.Fatalf("seeded %d DNS servers, want 1", len(servers))
	}

	reported := []HTTPListenerStatus{
		{Name: "cdn-assets", Addr: "0.0.0.0:8443", Scheme: "https", Source: "remote", Running: true, Enabled: true},
		{Name: "parked", Addr: "0.0.0.0:9443", Scheme: "http", Source: "remote", Enabled: false, Error: "bind: address already in use"},
	}
	encoded, err := json.Marshal(reported)
	if err != nil {
		t.Fatal(err)
	}

	if err := db.SetDNSServerHTTPListeners(servers[0].ID, string(encoded)); err != nil {
		t.Fatalf("SetDNSServerHTTPListeners() error = %v", err)
	}

	decoded := db.GetDNSServerHTTPListeners(servers[0].ID)
	if len(decoded) != 2 {
		t.Fatalf("decoded %d statuses, want 2", len(decoded))
	}
	if !decoded[0].Running || decoded[0].Name != "cdn-assets" {
		t.Errorf("first status = %+v, want cdn-assets running", decoded[0])
	}
	if decoded[1].Error == "" {
		t.Error("the failure reason was lost, so the UI cannot explain a listener that is not running")
	}

	// A malformed report yields an empty list, not an error.
	if err := db.SetDNSServerHTTPListeners(servers[0].ID, "{not json"); err != nil {
		t.Fatalf("storing a malformed report returned an error: %v", err)
	}
	if decoded := db.GetDNSServerHTTPListeners(servers[0].ID); len(decoded) != 0 {
		t.Fatalf("malformed report decoded to %+v, want empty", decoded)
	}
}

// TestHTTPListenerStatus_WireShapeWithServer pins the field names this struct shares with
// Server/http_registry.go.
//
// The two are separate Go modules, so the keys are the only thing joining them. A rename
// on one side would otherwise show up as a listener page that silently displays nothing,
// which is the kind of bug nobody reports.
func TestHTTPListenerStatus_WireShapeWithServer(t *testing.T) {
	// Exactly the JSON Server/http_registry.go emits.
	document := `[
		{
			"name": "cdn-assets",
			"addr": "0.0.0.0:8443",
			"scheme": "https",
			"source": "remote",
			"running": true,
			"enabled": true
		},
		{
			"name": "broken",
			"addr": "0.0.0.0:9443",
			"scheme": "http",
			"source": "file",
			"running": false,
			"enabled": true,
			"error": "listener certificate SPKI does not match the pinned value"
		}
	]`

	var statuses []HTTPListenerStatus
	if err := json.Unmarshal([]byte(document), &statuses); err != nil {
		t.Fatalf("failed to decode the reported state: %v", err)
	}
	if len(statuses) != 2 {
		t.Fatalf("decoded %d statuses, want 2", len(statuses))
	}

	first := statuses[0]
	if first.Name != "cdn-assets" || first.Addr != "0.0.0.0:8443" || first.Scheme != "https" ||
		first.Source != "remote" || !first.Running || !first.Enabled {
		t.Errorf("first status did not decode field for field: %+v", first)
	}

	second := statuses[1]
	if second.Running {
		t.Error("a listener reported as not running decoded as running")
	}
	if !strings.Contains(second.Error, "SPKI") {
		t.Errorf("the reported error was lost: %+v", second)
	}
}
