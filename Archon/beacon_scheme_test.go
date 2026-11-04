package main

import (
	"encoding/json"
	"testing"
)

// The shipped default serves plain HTTP behind a TLS-terminating Cloudflare proxy:
// the beacon DIALS https (beacon_scheme) while the served listener stays http. The
// two must stay independent — https-beacon must NOT demand a TLS pin, because for a
// Cloudflare front the certificate never exists on the origin.

func TestBeaconDialScheme(t *testing.T) {
	cases := []struct {
		served string
		beacon string
		want   string
	}{
		{"http", "", "http"}, // no beacon_scheme -> served scheme
		{"https", "", "https"},
		{"http", "https", "https"}, // Cloudflare front: dial https, serve http
		{"https", "http", "http"},
		{"http", " HTTPS ", "https"}, // normalized + trimmed
	}
	for _, tc := range cases {
		if got := beaconDialScheme(tc.served, tc.beacon); got != tc.want {
			t.Errorf("beaconDialScheme(%q, %q) = %q, want %q", tc.served, tc.beacon, got, tc.want)
		}
	}
}

func TestHTTPBeaconSchemeDoesNotDemandPin(t *testing.T) {
	// The shipped default is http-served with beacon_scheme https and no tls block:
	// it must pass the same validator the API uses. Demanding a pin here would refuse
	// exactly the Cloudflare deployment this default exists for.
	stored, err := normalizeHTTPProfileDocument(defaultHTTPProfileName, defaultHTTPProfileDocument())
	if err != nil {
		t.Fatalf("default profile with https beacon_scheme does not validate: %v", err)
	}
	var parsed struct {
		Scheme       string          `json:"scheme"`
		BeaconScheme string          `json:"beacon_scheme"`
		TLS          json.RawMessage `json:"tls,omitempty"`
	}
	if err := json.Unmarshal([]byte(stored), &parsed); err != nil {
		t.Fatalf("stored default is not JSON: %v", err)
	}
	if parsed.Scheme != "http" {
		t.Errorf("served scheme = %q, want http", parsed.Scheme)
	}
	if parsed.BeaconScheme != "https" {
		t.Errorf("beacon_scheme = %q, want https", parsed.BeaconScheme)
	}
	if len(parsed.TLS) != 0 {
		t.Errorf("default profile must ship no TLS material; got tls=%s", parsed.TLS)
	}
}

func TestHTTPListenerSpecHonorsBeaconScheme(t *testing.T) {
	spec, err := httpListenerSpecFromDocument(defaultHTTPProfileDocument())
	if err != nil {
		t.Fatalf("spec from default: %v", err)
	}
	if spec.Scheme != "https" {
		t.Errorf("spec.Scheme = %q, want https (beacon dials Cloudflare)", spec.Scheme)
	}
	if spec.Host != defaultHTTPProfileBeacon {
		t.Errorf("spec.Host = %q, want %q", spec.Host, defaultHTTPProfileBeacon)
	}
	if spec.SPKISHA256 != "" {
		t.Errorf("spec.SPKISHA256 = %q, want empty (Cloudflare cert, not pinned)", spec.SPKISHA256)
	}
}
