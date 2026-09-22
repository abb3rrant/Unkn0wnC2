package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newTestProfileDB creates a migrated database in a temp file.
func newTestProfileDB(t *testing.T) *MasterDatabase {
	t.Helper()

	path := filepath.Join(t.TempDir(), "profiles-test.db")
	db, err := NewMasterDatabase(path)
	if err != nil {
		t.Fatalf("NewMasterDatabase() error = %v", err)
	}
	t.Cleanup(func() {
		db.Close()
		os.Remove(path)
	})
	return db
}

// validProfileDocument is a minimal document that passes validation.
func validProfileDocument(t *testing.T) string {
	t.Helper()
	return `{
		"scheme": "http",
		"bind_port": 8080,
		"uris": {
			"register": ["/api/v1/ping"],
			"task": ["/api/v1/sync"],
			"result": ["/api/v1/report"],
			"ack": ["/api/v1/ack"]
		}
	}`
}

// =============================================================================
// Validation
// =============================================================================

// TestNormalizeHTTPProfileDocument_Accepts asserts a workable profile is stored
// with its name pinned, so the saved name and the profile's own name agree.
func TestNormalizeHTTPProfileDocument_Accepts(t *testing.T) {
	stored, err := normalizeHTTPProfileDocument("cdn-assets", validProfileDocument(t))
	if err != nil {
		t.Fatalf("normalizeHTTPProfileDocument() error = %v", err)
	}

	var document map[string]interface{}
	if err := json.Unmarshal([]byte(stored), &document); err != nil {
		t.Fatalf("stored document is not JSON: %v", err)
	}
	if document["name"] != "cdn-assets" {
		t.Errorf("stored name = %v, want cdn-assets", document["name"])
	}
	// Untouched fields must survive: the document is shipped verbatim.
	if document["bind_port"] != float64(8080) {
		t.Errorf("bind_port = %v, want 8080", document["bind_port"])
	}
}

// TestNormalizeHTTPProfileDocument_Table covers the rejection paths. Each message
// is what an operator sees in the form, so it must name the offending field.
func TestNormalizeHTTPProfileDocument_Table(t *testing.T) {
	tests := []struct {
		name     string
		record   string
		document string
		wantErr  string
	}{
		{
			name:     "empty name",
			record:   "",
			document: `{}`,
			wantErr:  "must be 1-64 characters",
		},
		{
			name:     "name with a path separator",
			record:   "../etc/passwd",
			document: `{}`,
			wantErr:  "must be 1-64 characters",
		},
		{
			name:     "name with a space",
			record:   "my profile",
			document: `{}`,
			wantErr:  "must be 1-64 characters",
		},
		{
			name:     "not JSON",
			record:   "edge",
			document: `not a document`,
			wantErr:  "not valid JSON",
		},
		{
			name:     "document renames itself",
			record:   "edge",
			document: `{"name":"other","uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "must match",
		},
		{
			name:     "bind port out of range",
			record:   "edge",
			document: `{"bind_port":99999,"uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "bind_port must be in range",
		},
		{
			name:     "unknown scheme",
			record:   "edge",
			document: `{"scheme":"ftp","uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "scheme must be",
		},
		{
			name:     "missing task URI",
			record:   "edge",
			document: `{"uris":{"register":["/a"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "uris.task needs at least one path",
		},
		{
			name:     "relative URI",
			record:   "edge",
			document: `{"uris":{"register":["/a"],"task":["sync"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  `must start with "/"`,
		},
		{
			name:     "https without cert",
			record:   "edge",
			document: `{"scheme":"https","uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "tls.cert_file and tls.key_file are required",
		},
		{
			name:   "https without a pin",
			record: "edge",
			document: `{"scheme":"https","tls":{"cert_file":"/c.crt","key_file":"/c.key"},
				"uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr: "tls.spki_sha256 is required",
		},
		{
			name:     "unknown request encoding",
			record:   "edge",
			document: `{"request_body":{"encoding":"rot13"},"uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "request_body.encoding must be one of",
		},
		{
			name:     "unknown auth mode",
			record:   "edge",
			document: `{"auth":{"mode":"basic"},"uris":{"register":["/a"],"task":["/b"],"result":["/c"],"ack":["/d"]}}`,
			wantErr:  "auth.mode must be",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := normalizeHTTPProfileDocument(tc.record, tc.document)
			if err == nil {
				t.Fatalf("normalizeHTTPProfileDocument() = nil, want error containing %q", tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want it to contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}

// =============================================================================
// Storage
// =============================================================================

// TestHTTPProfileStore_RoundTrip asserts profiles survive a save/read/replace/delete
// cycle, and that the table the migration creates is the one the queries use.
func TestHTTPProfileStore_RoundTrip(t *testing.T) {
	db := newTestProfileDB(t)

	stored, err := normalizeHTTPProfileDocument("cdn-assets", validProfileDocument(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHTTPProfile("cdn-assets", stored); err != nil {
		t.Fatalf("SaveHTTPProfile() error = %v", err)
	}

	record, err := db.GetHTTPProfile("cdn-assets")
	if err != nil {
		t.Fatalf("GetHTTPProfile() error = %v", err)
	}
	if record.Name != "cdn-assets" {
		t.Errorf("Name = %q, want cdn-assets", record.Name)
	}
	if !strings.Contains(record.Document, "/api/v1/sync") {
		t.Errorf("stored document lost its contents: %s", record.Document)
	}
	if record.UpdatedAt.IsZero() {
		t.Error("UpdatedAt was not recorded")
	}

	// A second profile shows up in the listing.
	if err := db.SaveHTTPProfile("edge", stored); err != nil {
		t.Fatal(err)
	}
	records, err := db.ListHTTPProfiles()
	if err != nil {
		t.Fatalf("ListHTTPProfiles() error = %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("ListHTTPProfiles() returned %d records, want 2", len(records))
	}
	if records[0].Name != "cdn-assets" || records[1].Name != "edge" {
		t.Errorf("profiles are not sorted by name: %s, %s", records[0].Name, records[1].Name)
	}

	// Saving the same name replaces rather than duplicating.
	replaced, err := normalizeHTTPProfileDocument("cdn-assets", `{
		"scheme": "http",
		"bind_port": 9090,
		"uris": {"register":["/x"],"task":["/y"],"result":["/z"],"ack":["/w"]}
	}`)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.SaveHTTPProfile("cdn-assets", replaced); err != nil {
		t.Fatal(err)
	}
	records, err = db.ListHTTPProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("replacing a profile changed the count to %d, want 2", len(records))
	}
	record, err = db.GetHTTPProfile("cdn-assets")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(record.Document, "9090") {
		t.Errorf("replacement was not stored: %s", record.Document)
	}

	// Deleting removes only the named profile.
	if err := db.DeleteHTTPProfile("edge"); err != nil {
		t.Fatalf("DeleteHTTPProfile() error = %v", err)
	}
	if _, err := db.GetHTTPProfile("edge"); err == nil {
		t.Error("deleted profile is still readable")
	}
	records, err = db.ListHTTPProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("after delete, %d records remain, want 1", len(records))
	}
}

// TestHTTPProfileStore_MissingProfileIsAnError asserts a lookup of an unknown name
// reports absence rather than an empty record.
func TestHTTPProfileStore_MissingProfileIsAnError(t *testing.T) {
	db := newTestProfileDB(t)

	if _, err := db.GetHTTPProfile("nope"); err == nil {
		t.Fatal("GetHTTPProfile() returned no error for an unknown name")
	}
}

// =============================================================================
// Runtime update payload
// =============================================================================

// TestBuildTransportUpdatePayload asserts the payload a beacon receives is exactly
// the shape its ApplyUpdate parses, and that an unusable mode is refused before
// anything is queued.
func TestBuildTransportUpdatePayload(t *testing.T) {
	listener := HTTPListenerSpec{
		Name:   "cdn-assets",
		Scheme: "https",
		Host:   "cdn.example.com:8443",
		URIs: map[string][]string{
			"register": {"/api/v1/ping"},
			"task":     {"/api/v1/sync"},
			"result":   {"/api/v1/report"},
			"ack":      {"/api/v1/ack"},
		},
	}

	t.Run("dual with a listener", func(t *testing.T) {
		payload, err := buildTransportUpdatePayload("dual", []HTTPListenerSpec{listener}, 5, 30)
		if err != nil {
			t.Fatalf("buildTransportUpdatePayload() error = %v", err)
		}

		// The beacon reads these keys through its transportUpdate type; assert the
		// wire names rather than trusting the marshal.
		var document map[string]interface{}
		if err := json.Unmarshal([]byte(payload), &document); err != nil {
			t.Fatalf("payload is not JSON: %v", err)
		}
		for _, key := range []string{"mode", "listeners", "fallback_after_failures", "retry_backoff_secs"} {
			if _, ok := document[key]; !ok {
				t.Errorf("payload has no %q key: %s", key, payload)
			}
		}
		if document["mode"] != "dual" {
			t.Errorf("mode = %v, want dual", document["mode"])
		}
		if document["fallback_after_failures"] != float64(5) {
			t.Errorf("fallback_after_failures = %v, want 5", document["fallback_after_failures"])
		}
	})

	t.Run("dns needs no listener", func(t *testing.T) {
		if _, err := buildTransportUpdatePayload("dns", nil, 0, 0); err != nil {
			t.Fatalf("buildTransportUpdatePayload(dns) error = %v", err)
		}
	})

	t.Run("http without a listener is refused", func(t *testing.T) {
		if _, err := buildTransportUpdatePayload("http", nil, 0, 0); err == nil {
			t.Fatal("buildTransportUpdatePayload(http) accepted no listeners")
		}
	})

	t.Run("unknown mode is refused", func(t *testing.T) {
		if _, err := buildTransportUpdatePayload("carrier-pigeon", []HTTPListenerSpec{listener}, 0, 0); err == nil {
			t.Fatal("buildTransportUpdatePayload() accepted an unknown mode")
		}
	})

	t.Run("mode is case-insensitive", func(t *testing.T) {
		payload, err := buildTransportUpdatePayload("DUAL", []HTTPListenerSpec{listener}, 0, 0)
		if err != nil {
			t.Fatalf("buildTransportUpdatePayload(DUAL) error = %v", err)
		}
		if !strings.Contains(payload, `"mode":"dual"`) {
			t.Errorf("mode was not normalised: %s", payload)
		}
	})
}

// TestQueueTransportUpdate_CreatesFireAndForgetTask asserts the queued task uses
// the prefix the server and client both treat as fire-and-forget, since a task
// that expects a result would leave the beacon's queue blocked on a reply it never
// sends.
func TestQueueTransportUpdate_CreatesFireAndForgetTask(t *testing.T) {
	db := newTestProfileDB(t)

	if err := createTestBeacon(db, "beacon-1"); err != nil {
		t.Fatalf("failed to seed a beacon: %v", err)
	}

	api := &APIServer{db: db}

	payload, err := buildTransportUpdatePayload("dual", []HTTPListenerSpec{{
		Name: "cdn-assets",
		Host: "cdn.example.com:8443",
		URIs: map[string][]string{"task": {"/api/v1/sync"}},
	}}, 3, 60)
	if err != nil {
		t.Fatal(err)
	}

	if err := api.queueTransportUpdate("beacon-1", payload); err != nil {
		t.Fatalf("queueTransportUpdate() error = %v", err)
	}

	// Read the queue back the way the DNS server would see it, so the assertion is
	// about the task row that will actually be delivered.
	tasks, err := db.GetTasksForDNSServer("dns1")
	if err != nil {
		t.Fatalf("GetTasksForDNSServer() error = %v", err)
	}
	if len(tasks) == 0 {
		t.Fatal("no task was queued")
	}

	var found bool
	for _, task := range tasks {
		if strings.HasPrefix(task.Command, "update_transport:") {
			found = true
			if !strings.Contains(task.Command, `"mode":"dual"`) {
				t.Errorf("queued command lost its payload: %s", task.Command)
			}
		}
	}
	if !found {
		t.Fatalf("no update_transport task was queued; got %+v", tasks)
	}
}
