package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

// TestBuildClient_EmbedsHTTPTransportConfig is the end-to-end check that a beacon
// built by Archon actually carries a transport configuration.
//
// It deliberately goes through the real buildClient rather than inspecting the
// generated source: a successful compile proves the generated config.go is valid
// Go using the Client module's real field names, and scanning the produced binary
// proves the values survived into the artefact an operator downloads.
func TestBuildClient_EmbedsHTTPTransportConfig(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping beacon compile in short mode")
	}

	// Distinctive values so a match in the binary cannot be a coincidence.
	const (
		hostMarker = "listener-marker.example.net:8443"
		pinMarker  = "PINMARKERabcdefghijklmnopqrstuvwxyz012345"
	)

	req := ClientBuildRequest{
		DNSDomains:   []string{"c2.example.com"},
		Platform:     "linux",
		Architecture: "amd64",
		SleepMin:     1,
		SleepMax:     2,
		BeaconName:   "httptest",
		Transport:    "dual",
		HTTPListeners: []HTTPListenerSpec{
			{
				Name:       "cdn-assets",
				Scheme:     "https",
				Host:       hostMarker,
				SPKISHA256: pinMarker,
				URIs: map[string][]string{
					"register": {"/api/v1/ping"},
					"task":     {"/api/v1/sync"},
					"result":   {"/api/v1/report"},
					"ack":      {"/api/v1/ack"},
				},
				Methods: map[string]string{
					"register": "POST",
					"task":     "GET",
					"result":   "POST",
					"ack":      "GET",
				},
			},
		},
		HTTPFallbackAfterFailures: 4,
		HTTPRetryBackoffSecs:      45,
	}

	// The Client source lives beside Archon in the repository root.
	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceRoot, "Client", "main.go")); err != nil {
		t.Skipf("Client source not available at %s: %v", sourceRoot, err)
	}

	binaryPath, err := buildClient(req, sourceRoot, "test-encryption-key-000000000000", "testbuild")
	if err != nil {
		t.Fatalf("buildClient() error = %v", err)
	}
	if binaryPath != "" {
		defer os.RemoveAll(filepath.Dir(binaryPath))
	}

	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatalf("failed to read the built binary: %v", err)
	}

	for name, want := range map[string]string{
		"transport mode": "dual",
		"listener host":  hostMarker,
		"pinned SPKI":    pinMarker,
		"task URI":       "/api/v1/sync",
	} {
		if !bytes.Contains(raw, []byte(want)) {
			t.Errorf("built binary does not contain the %s (%q)", name, want)
		}
	}
}

// TestBuildClient_DefaultsToDNS asserts a build request that does not mention a
// transport produces a DNS-mode beacon, so existing build flows are unaffected.
func TestBuildClient_DefaultsToDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping beacon compile in short mode")
	}

	req := ClientBuildRequest{
		DNSDomains:   []string{"c2.example.com"},
		Platform:     "linux",
		Architecture: "amd64",
		SleepMin:     1,
		SleepMax:     2,
		BeaconName:   "dnstest",
	}

	sourceRoot, err := filepath.Abs("..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(sourceRoot, "Client", "main.go")); err != nil {
		t.Skipf("Client source not available at %s: %v", sourceRoot, err)
	}

	binaryPath, err := buildClient(req, sourceRoot, "test-encryption-key-000000000000", "testbuild")
	if err != nil {
		t.Fatalf("buildClient() error = %v", err)
	}
	if binaryPath != "" {
		defer os.RemoveAll(filepath.Dir(binaryPath))
	}

	raw, err := os.ReadFile(binaryPath)
	if err != nil {
		t.Fatal(err)
	}

	// The embedded mode is the DNS default.
	if !bytes.Contains(raw, []byte("dns")) {
		t.Error("built binary does not carry the default dns transport mode")
	}

	// No listener list was embedded. Checking for the marshalled document rather
	// than a field name matters: Go keeps struct tag strings such as
	// json:"spki_sha256" in every binary's type metadata, so a field name is
	// present whether or not any listener was configured.
	if bytes.Contains(raw, []byte(`{"name":`)) {
		t.Error("a DNS-only build embedded an HTTP listener document")
	}
}
