package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// The shipped default profile is only useful if it is (a) valid against the same
// validator the API uses and (b) usable by a beacon build. Both are asserted here,
// because a default that a listener refuses to start is worse than no default.

func TestDefaultHTTPProfileDocument_IsStorable(t *testing.T) {
	document := defaultHTTPProfileDocument()

	stored, err := normalizeHTTPProfileDocument(defaultHTTPProfileName, document)
	if err != nil {
		t.Fatalf("the shipped default profile does not validate: %v", err)
	}

	var parsed struct {
		Name           string `json:"name"`
		Scheme         string `json:"scheme"`
		BindPort       int    `json:"bind_port"`
		BeaconHost     string `json:"beacon_host"`
		BeaconScheme   string `json:"beacon_scheme"`
		URIs           map[string][]string
		RequestHeaders []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"request_headers"`
	}
	if err := json.Unmarshal([]byte(stored), &parsed); err != nil {
		t.Fatalf("stored default profile is not JSON: %v", err)
	}

	if parsed.Name != defaultHTTPProfileName {
		t.Errorf("name = %q, want %q", parsed.Name, defaultHTTPProfileName)
	}
	if parsed.Scheme != "http" {
		t.Errorf("scheme = %q, want http: an https default cannot ship a pin that matches a listener's certificate", parsed.Scheme)
	}
	if parsed.BindPort != defaultHTTPProfileBindPort {
		t.Errorf("bind_port = %d, want %d", parsed.BindPort, defaultHTTPProfileBindPort)
	}
	if parsed.BeaconHost == "" {
		t.Error("beacon_host is empty, so the builder refuses to build a beacon from the default")
	}
	// The served listener is http, but the beacon must DIAL https so builds from the
	// default are HTTPS through a Cloudflare front with no certificate to manage.
	if parsed.BeaconScheme != "https" {
		t.Errorf("beacon_scheme = %q, want https (Cloudflare HTTPS default)", parsed.BeaconScheme)
	}
	for _, operation := range []string{"register", "task", "result", "ack"} {
		if len(parsed.URIs[operation]) == 0 {
			t.Errorf("uris.%s is empty", operation)
		}
	}

	// Host, Content-Length on body operations and the auth header are what the
	// listener's fingerprint check requires; absent any of them the profile is
	// stored but no beacon can check in.
	wanted := map[string]string{"Host": "{{host}}", "Content-Length": "{{content_length}}", "X-Sig": "{{auth}}"}
	for name, value := range wanted {
		found := false
		for _, header := range parsed.RequestHeaders {
			if header.Name == name && header.Value == value {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("request_headers is missing %s: %s", name, value)
		}
	}

	if strings.Contains(document, "REPLACE_WITH_GENERATED_PIN") {
		t.Error("default profile still carries the placeholder pin")
	}
}

func TestEnsureDefaultHTTPProfile_SeedsOnlyAnEmptyStore(t *testing.T) {
	db := newTestProfileDB(t)

	seeded, err := db.EnsureDefaultHTTPProfile()
	if err != nil {
		t.Fatalf("EnsureDefaultHTTPProfile() error = %v", err)
	}
	if !seeded {
		t.Fatal("expected the default profile to be seeded into an empty store")
	}

	record, err := db.GetHTTPProfile(defaultHTTPProfileName)
	if err != nil {
		t.Fatalf("seeded profile cannot be read back: %v", err)
	}
	if _, err := normalizeHTTPProfileDocument(defaultHTTPProfileName, record.Document); err != nil {
		t.Errorf("seeded profile does not validate: %v", err)
	}

	// Idempotent: a second start must not duplicate or overwrite it.
	if seeded, err := db.EnsureDefaultHTTPProfile(); err != nil || seeded {
		t.Errorf("second call = (%v, %v), want (false, nil)", seeded, err)
	}

	// And it must not come back after an operator deletes it while other profiles
	// exist, which is the difference between a seed and a nag.
	if err := db.SaveHTTPProfile("operator-authored", validProfileDocument(t)); err != nil {
		t.Fatalf("saving an operator profile: %v", err)
	}
	if err := db.DeleteHTTPProfile(defaultHTTPProfileName); err != nil {
		t.Fatalf("deleting the seeded profile: %v", err)
	}
	if seeded, err := db.EnsureDefaultHTTPProfile(); err != nil || seeded {
		t.Errorf("re-seed with an existing profile = (%v, %v), want (false, nil)", seeded, err)
	}
	if _, err := db.GetHTTPProfile(defaultHTTPProfileName); err == nil {
		t.Error("the default profile was re-created after it had been deleted")
	}
}

func TestHTTPProfileTemplateHandler_ServesTheSeededDocument(t *testing.T) {
	api := NewAPIServer(newTestProfileDB(t), Config{})

	recorder := httptest.NewRecorder()
	api.handleHTTPProfileTemplate(recorder, httptest.NewRequest("GET", "/api/http/profile-template", nil))

	if recorder.Code != 200 {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}

	var response struct {
		Data struct {
			Name     string `json:"name"`
			Document string `json:"document"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}

	if response.Data.Name != defaultHTTPProfileName {
		t.Errorf("name = %q, want %q", response.Data.Name, defaultHTTPProfileName)
	}
	if response.Data.Document != defaultHTTPProfileDocument() {
		t.Error("the served template differs from the seeded document")
	}
}
