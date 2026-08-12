package main

import (
	"encoding/json"
	"testing"
	"time"
)

// These tests verify the typed struct accessors introduced by the most recent
// commit (ui-fixes: conversion of map[string]interface{} database access to
// typed structs defined in types.go).

func TestGetBuildConfigByBuildIDTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	buildConfig := `{"payload_format":"CHK.XXXX.XXXXXXXX","registration_phase":{"query_type":"A","encrypted":true,"a_record_ack_ip":"1.2.3.4"}}`
	if err := db.SaveClientBinary("cb-typed-1", "client", "linux", "amd64", "1.0.0",
		"QUJD", "c2.example.com", 100, 90, 120, 370, 2, "", "build-abc-1", buildConfig); err != nil {
		t.Fatalf("SaveClientBinary failed: %v", err)
	}

	bc, err := db.GetBuildConfigByBuildID("build-abc-1")
	if err != nil {
		t.Fatalf("GetBuildConfigByBuildID failed: %v", err)
	}

	if bc.BinaryID != "cb-typed-1" {
		t.Errorf("BinaryID: expected cb-typed-1, got %q", bc.BinaryID)
	}
	if bc.BuildID != "build-abc-1" {
		t.Errorf("BuildID: expected build-abc-1, got %q", bc.BuildID)
	}
	if bc.OS != "linux" || bc.Arch != "amd64" {
		t.Errorf("OS/Arch: expected linux/amd64, got %s/%s", bc.OS, bc.Arch)
	}
	if bc.DNSDomains != "c2.example.com" {
		t.Errorf("DNSDomains: expected c2.example.com, got %q", bc.DNSDomains)
	}
	if bc.Extra == nil {
		t.Fatal("Extra map should be populated from build_config JSON")
	}
	if pf, _ := bc.Extra["payload_format"].(string); pf != "CHK.XXXX.XXXXXXXX" {
		t.Errorf("payload_format in Extra: expected CHK.XXXX.XXXXXXXX, got %v", bc.Extra["payload_format"])
	}

	// Verify the typed struct marshals back to the flattened JSON contract
	raw, err := json.Marshal(bc)
	if err != nil {
		t.Fatalf("Marshal BuildConfig failed: %v", err)
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("Unmarshal BuildConfig JSON failed: %v", err)
	}
	if m["binary_id"] != "cb-typed-1" {
		t.Errorf("flattened binary_id missing: %v", m)
	}
	if m["payload_format"] != "CHK.XXXX.XXXXXXXX" {
		t.Errorf("flattened payload_format missing: %v", m)
	}
}

func TestGetBuildConfigByBuildIDNotFoundTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	bc, err := db.GetBuildConfigByBuildID("does-not-exist")
	if err != nil {
		t.Fatalf("expected no error for missing build: %v", err)
	}
	if bc.BinaryID != "" {
		t.Errorf("expected empty BuildConfig, got BinaryID=%q", bc.BinaryID)
	}
}

func TestGetBuildPhaseConfigsTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	withIP := `{
		"registration_phase": {"query_type": "A", "encrypted": true, "a_record_ack_ip": "1.2.3.4"},
		"poll_phase": {"query_type": "A", "a_record_task_ip": "5.6.7.8", "txt_follow_up_secs": 30},
		"data_exfil_phase": {"query_type": "TXT", "encrypted": true}
	}`
	withoutIP := `{"registration_phase": {"query_type": "A", "encrypted": false}}`

	if err := db.SaveClientBinary("cb-phase-1", "client", "linux", "amd64", "1.0.0",
		"QUJD", "c2.example.com", 100, 90, 120, 370, 2, "", "build-phase-1", withIP); err != nil {
		t.Fatalf("SaveClientBinary (withIP) failed: %v", err)
	}
	if err := db.SaveClientBinary("cb-phase-2", "client", "linux", "amd64", "1.0.0",
		"QUJD", "c2.example.com", 100, 90, 120, 370, 2, "", "build-phase-2", withoutIP); err != nil {
		t.Fatalf("SaveClientBinary (withoutIP) failed: %v", err)
	}

	configs, err := db.GetBuildPhaseConfigs()
	if err != nil {
		t.Fatalf("GetBuildPhaseConfigs failed: %v", err)
	}

	if len(configs) != 1 {
		t.Fatalf("expected only the build with a_record_ack_ip (1 config), got %d: %v", len(configs), configs)
	}

	pc, ok := configs["build-phase-1"]
	if !ok {
		t.Fatalf("expected config keyed by build_id build-phase-1, got keys: %v", configs)
	}
	if qt, _ := pc.RegistrationPhase["query_type"].(string); qt != "A" {
		t.Errorf("registration query_type: expected A, got %v", pc.RegistrationPhase["query_type"])
	}
	if enc, _ := pc.RegistrationPhase["encrypted"].(bool); !enc {
		t.Errorf("registration encrypted: expected true, got %v", pc.RegistrationPhase["encrypted"])
	}
	if ip, _ := pc.RegistrationPhase["a_record_ack_ip"].(string); ip != "1.2.3.4" {
		t.Errorf("registration a_record_ack_ip: expected 1.2.3.4, got %v", pc.RegistrationPhase["a_record_ack_ip"])
	}
	if ip, _ := pc.PollPhase["a_record_task_ip"].(string); ip != "5.6.7.8" {
		t.Errorf("poll a_record_task_ip: expected 5.6.7.8, got %v", pc.PollPhase["a_record_task_ip"])
	}
	if secs, _ := pc.PollPhase["txt_follow_up_secs"].(int); secs != 30 {
		t.Errorf("poll txt_follow_up_secs: expected 30, got %v", pc.PollPhase["txt_follow_up_secs"])
	}
	if qt, _ := pc.DataExfilPhase["query_type"].(string); qt != "TXT" {
		t.Errorf("data_exfil query_type: expected TXT, got %v", pc.DataExfilPhase["query_type"])
	}
}

func TestGetPendingStagerCachesTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	if err := db.RegisterDNSServer("dns-cache-1", "c2.cache.com", "10.0.0.9", "cache-key"); err != nil {
		t.Fatalf("RegisterDNSServer failed: %v", err)
	}

	// base64_data longer than one 370-byte chunk to verify chunking
	longData := ""
	for i := 0; i < 1000; i++ {
		longData += "A"
	}
	if err := db.SaveClientBinary("cb-cache-1", "client", "linux", "amd64", "1.0.0",
		longData, "c2.example.com", 100, 90, 120, 370, 3, "", "build-cache-1", ""); err != nil {
		t.Fatalf("SaveClientBinary failed: %v", err)
	}

	if err := db.QueueStagerCacheForDNSServers("cb-cache-1", []string{"dns-cache-1"}); err != nil {
		t.Fatalf("QueueStagerCacheForDNSServers failed: %v", err)
	}

	caches, err := db.GetPendingStagerCaches("dns-cache-1")
	if err != nil {
		t.Fatalf("GetPendingStagerCaches failed: %v", err)
	}
	if len(caches) != 1 {
		t.Fatalf("expected 1 pending cache, got %d", len(caches))
	}

	cache := caches[0]
	if cache.ID == 0 {
		t.Errorf("expected a populated ID, got 0")
	}
	if cache.ClientBinaryID != "cb-cache-1" {
		t.Errorf("ClientBinaryID: expected cb-cache-1, got %q", cache.ClientBinaryID)
	}
	if cache.TotalChunks != 3 {
		t.Errorf("TotalChunks: expected 3, got %d", cache.TotalChunks)
	}

	// base64_data (1000 chars) is chunked at 370 bytes each
	expectedChunks := (len(longData) + 370 - 1) / 370
	if len(cache.Chunks) != expectedChunks {
		t.Fatalf("expected %d chunks, got %d", expectedChunks, len(cache.Chunks))
	}
	var reassembled string
	for _, c := range cache.Chunks {
		reassembled += c
	}
	if reassembled != longData {
		t.Error("reassembled chunks do not match original base64_data")
	}
}

func TestGetStagerChunksForDNSServerTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	if err := db.RegisterDNSServer("dns-chunk-1", "c2.chunk1.com", "10.0.0.10", "key1"); err != nil {
		t.Fatalf("RegisterDNSServer 1 failed: %v", err)
	}
	if err := db.RegisterDNSServer("dns-chunk-2", "c2.chunk2.com", "10.0.0.11", "key2"); err != nil {
		t.Fatalf("RegisterDNSServer 2 failed: %v", err)
	}
	if err := db.SaveClientBinary("cb-chunk-1", "client", "linux", "amd64", "1.0.0",
		"QUJD", "c2.example.com", 100, 90, 120, 370, 3, "", "build-chunk-1", ""); err != nil {
		t.Fatalf("SaveClientBinary failed: %v", err)
	}
	if err := db.CreateStagerSession("sess-1", "10.0.0.50", "linux", "amd64", "cb-chunk-1", "dns-chunk-1", 3); err != nil {
		t.Fatalf("CreateStagerSession failed: %v", err)
	}

	chunks := []string{"AAA", "BBB", "CCC"}
	if err := db.AssignStagerChunks("sess-1", "cb-chunk-1", chunks, []string{"dns-chunk-1", "dns-chunk-2"}); err != nil {
		t.Fatalf("AssignStagerChunks failed: %v", err)
	}

	// Round-robin: index 0 -> dns-chunk-1, 1 -> dns-chunk-2, 2 -> dns-chunk-1
	s1, err := db.GetStagerChunksForDNSServer("sess-1", "dns-chunk-1")
	if err != nil {
		t.Fatalf("GetStagerChunksForDNSServer (dns-chunk-1) failed: %v", err)
	}
	if len(s1) != 2 {
		t.Fatalf("expected 2 chunks for dns-chunk-1, got %d", len(s1))
	}
	if s1[0].ChunkIndex != 0 || s1[0].ChunkData != "AAA" {
		t.Errorf("chunk 0: expected index 0 data AAA, got %+v", s1[0])
	}
	if s1[1].ChunkIndex != 2 || s1[1].ChunkData != "CCC" {
		t.Errorf("chunk 1: expected index 2 data CCC, got %+v", s1[1])
	}

	s2, err := db.GetStagerChunksForDNSServer("sess-1", "dns-chunk-2")
	if err != nil {
		t.Fatalf("GetStagerChunksForDNSServer (dns-chunk-2) failed: %v", err)
	}
	if len(s2) != 1 || s2[0].ChunkIndex != 1 || s2[0].ChunkData != "BBB" {
		t.Fatalf("expected only index 1 / BBB for dns-chunk-2, got %+v", s2)
	}
}

func TestGetBeaconDNSContactsTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beaconID := "typed-beacon-contacts"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("createTestBeacon failed: %v", err)
	}

	if err := db.RegisterDNSServer("dns-c-1", "c2.one.com", "10.0.0.20", "key-c-1"); err != nil {
		t.Fatalf("RegisterDNSServer 1 failed: %v", err)
	}
	if err := db.RegisterDNSServer("dns-c-2", "c2.two.com", "10.0.0.21", "key-c-2"); err != nil {
		t.Fatalf("RegisterDNSServer 2 failed: %v", err)
	}

	if err := db.RecordBeaconDNSContact(beaconID, "dns-c-1", "c2.one.com"); err != nil {
		t.Fatalf("RecordBeaconDNSContact 1 failed: %v", err)
	}
	if err := db.RecordBeaconDNSContact(beaconID, "dns-c-2", "c2.two.com"); err != nil {
		t.Fatalf("RecordBeaconDNSContact 2 failed: %v", err)
	}

	contacts, err := db.GetBeaconDNSContacts(beaconID)
	if err != nil {
		t.Fatalf("GetBeaconDNSContacts failed: %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts, got %d", len(contacts))
	}

	seen := map[string]bool{}
	for _, c := range contacts {
		if c.DNSDomain != "c2.one.com" && c.DNSDomain != "c2.two.com" {
			t.Errorf("unexpected DNSDomain %q", c.DNSDomain)
		}
		seen[c.DNSDomain] = true
		if c.DNSStatus != "active" {
			t.Errorf("contact %q: expected active status, got %q", c.DNSDomain, c.DNSStatus)
		}
		if _, err := time.Parse(time.RFC3339, c.FirstContact); err != nil {
			t.Errorf("contact %q: FirstContact not RFC3339: %v", c.DNSDomain, err)
		}
		if _, err := time.Parse(time.RFC3339, c.LastContact); err != nil {
			t.Errorf("contact %q: LastContact not RFC3339: %v", c.DNSDomain, err)
		}
	}
	if !seen["c2.one.com"] || !seen["c2.two.com"] {
		t.Errorf("expected both domains, got %v", seen)
	}

	// Contacts older than 30 minutes should report as inactive
	if _, err := db.db.Exec(`UPDATE beacon_dns_contacts SET last_contact = ? WHERE beacon_id = ?`,
		time.Now().Add(-2*time.Hour).Unix(), beaconID); err != nil {
		t.Fatalf("failed to age contact: %v", err)
	}
	contacts, err = db.GetBeaconDNSContacts(beaconID)
	if err != nil {
		t.Fatalf("GetBeaconDNSContacts (aged) failed: %v", err)
	}
	if len(contacts) != 2 {
		t.Fatalf("expected 2 contacts after aging, got %d", len(contacts))
	}
	for _, c := range contacts {
		if c.DNSStatus != "inactive" {
			t.Errorf("contact %q: expected inactive status after aging, got %q", c.DNSDomain, c.DNSStatus)
		}
	}
}

func TestGetDNSServerBeaconsTyped(t *testing.T) {
	db, cleanup := newTestDB(t)
	defer cleanup()

	beaconID := "typed-server-beacons"
	if err := createTestBeacon(db, beaconID); err != nil {
		t.Fatalf("createTestBeacon failed: %v", err)
	}

	if err := db.RegisterDNSServer("dns-sb-1", "c2.sb.com", "10.0.0.30", "key-sb-1"); err != nil {
		t.Fatalf("RegisterDNSServer 1 failed: %v", err)
	}
	if err := db.RegisterDNSServer("dns-sb-other", "c2.other.com", "10.0.0.31", "key-sb-2"); err != nil {
		t.Fatalf("RegisterDNSServer 2 failed: %v", err)
	}

	if err := db.RecordBeaconDNSContact(beaconID, "dns-sb-1", "c2.sb.com"); err != nil {
		t.Fatalf("RecordBeaconDNSContact failed: %v", err)
	}

	beacons, err := db.GetDNSServerBeacons("dns-sb-1", 60)
	if err != nil {
		t.Fatalf("GetDNSServerBeacons failed: %v", err)
	}
	if len(beacons) != 1 {
		t.Fatalf("expected 1 beacon, got %d", len(beacons))
	}

	b := beacons[0]
	if b.BeaconID != beaconID {
		t.Errorf("BeaconID: expected %s, got %q", beaconID, b.BeaconID)
	}
	if b.Hostname != "testhost" {
		t.Errorf("Hostname: expected testhost, got %q", b.Hostname)
	}
	if _, err := time.Parse(time.RFC3339, b.LastSeen); err != nil {
		t.Errorf("LastSeen not RFC3339: %v", err)
	}

	// Contact from another DNS server should not appear for this server
	if err := db.RecordBeaconDNSContact(beaconID, "dns-sb-other", "c2.other.com"); err != nil {
		t.Fatalf("RecordBeaconDNSContact (other) failed: %v", err)
	}
	beacons, err = db.GetDNSServerBeacons("dns-sb-1", 60)
	if err != nil {
		t.Fatalf("GetDNSServerBeacons (after other contact) failed: %v", err)
	}
	if len(beacons) != 1 {
		t.Fatalf("expected still 1 beacon for dns-sb-1, got %d", len(beacons))
	}
}
