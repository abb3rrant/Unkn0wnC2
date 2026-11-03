package main

import (
	"testing"
	"time"
)

// TestBeaconHTTPContactsRecordSeparately covers the reason the table exists: a
// beacon that reaches the same listener over both transports must produce one row
// per transport, and repeat contacts must accumulate rather than duplicate.
func TestBeaconHTTPContactsRecordSeparately(t *testing.T) {
	db := newTestProfileDB(t)

	now := time.Now()
	if err := db.UpsertBeacon("beacon-http", "host", "user", "linux", "amd64", "10.0.0.5",
		"listener-1", now, now, "http-beacon", "", "", "", nil); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	if err := db.RegisterDNSServer("listener-1", "alpha.test", "10.0.0.10", "key"); err != nil {
		t.Fatalf("seed listener: %v", err)
	}

	for i := 0; i < 3; i++ {
		if err := db.RecordBeaconHTTPContact("beacon-http", "listener-1", "default"); err != nil {
			t.Fatalf("record contact: %v", err)
		}
	}
	// A second profile on the same listener is a different contact, not an update.
	if err := db.RecordBeaconHTTPContact("beacon-http", "listener-1", "cdn-assets"); err != nil {
		t.Fatalf("record second profile: %v", err)
	}

	contacts, err := db.GetBeaconHTTPContacts("beacon-http")
	if err != nil {
		t.Fatalf("get contacts: %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts (one per profile), got %d", len(contacts))
	}

	byName := map[string]HTTPContact{}
	for _, contact := range contacts {
		byName[contact.ListenerName] = contact
	}
	if got := byName["default"].ContactCount; got != 3 {
		t.Errorf("default profile contact_count = %d, want 3", got)
	}
	if got := byName["cdn-assets"].ContactCount; got != 1 {
		t.Errorf("cdn-assets contact_count = %d, want 1", got)
	}
	if got := byName["default"].ListenerAddr; got != "10.0.0.10" {
		t.Errorf("listener address = %q, want the joined server address", got)
	}

	// An HTTP contact must not fabricate a DNS contact for the same beacon.
	dnsContacts, err := db.GetBeaconDNSContacts("beacon-http")
	if err != nil {
		t.Fatalf("get dns contacts: %v", err)
	}
	if len(dnsContacts) != 0 {
		t.Errorf("HTTP contact created %d DNS contact(s)", len(dnsContacts))
	}
}

// TestBeaconTransportFallback pins the behaviour that keeps an HTTP beacon's
// contact out of the DNS history when the reporting listener does not name the
// transport.
func TestBeaconTransportFallback(t *testing.T) {
	db := newTestProfileDB(t)

	now := time.Now()
	if err := db.UpsertBeacon("beacon-dual", "host", "user", "linux", "amd64", "10.0.0.6",
		"listener-1", now, now, "", "", "", "", nil); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	if got := db.GetBeaconTransport("beacon-dual"); got != "" {
		t.Fatalf("fresh beacon transport = %q, want empty", got)
	}

	if err := db.SetBeaconHTTPListeners("beacon-dual", []string{"default"}, "http"); err != nil {
		t.Fatalf("set transport: %v", err)
	}
	if got := db.GetBeaconTransport("beacon-dual"); got != "http" {
		t.Errorf("recorded transport = %q, want http", got)
	}
}
