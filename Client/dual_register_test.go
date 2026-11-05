package main

import (
	"testing"
	"time"
)

// testDNSClient builds a DNSClient with the internal selection maps initialised
// (the real constructor does this; a bare struct literal leaves them nil).
func testDNSClient(cfg *Config, key []byte) *DNSClient {
	return &DNSClient{
		config:        cfg,
		aesKey:        key,
		failedDomains: make(map[string]time.Time),
		domainLatency: make(map[string]time.Duration),
		successCounts: make(map[string]int),
		failureCounts: make(map[string]int),
	}
}

// A dual registration must prove both transports. When DNS cannot be resolved
// but HTTP answers, the beacon registers and latches to HTTP (the dead DNS side
// is not silently assumed healthy).
func TestRegisterDual_LatchesToHTTPWhenDNSFails(t *testing.T) {
	key := testKey()
	addr, _ := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	cfg := &Config{
		Transport:     "dual",
		DNSDomains:    []string{"nope.invalid"},
		HTTPListeners: []HTTPListener{testListener(addr, nil)},
		Timeout:       1,
		RetryAttempts: 1,
		QueryType:     "TXT",
	}
	m := newTransportManager(cfg, key)
	b := &Beacon{transport: m, client: testDNSClient(cfg, key)}

	if !b.registerDual("CHK|b|h|u|linux|amd64", cfg.GetRegistrationPhase()) {
		t.Fatal("registerDual returned false even though HTTP answered")
	}
	if m.Mode() != transportHTTP || !m.Latched() {
		t.Fatalf("after DNS-fail/HTTP-ok: mode=%q latched=%v, want http/true", m.Mode(), m.Latched())
	}
}

// When neither transport answers, registration fails and the beacon keeps DNS
// as the best-effort default rather than claiming success.
func TestRegisterDual_BothDead(t *testing.T) {
	key := testKey()
	cfg := &Config{
		Transport:     "dual",
		DNSDomains:    []string{"nope.invalid"},
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
		Timeout:       1,
		RetryAttempts: 1,
		QueryType:     "TXT",
	}
	m := newTransportManager(cfg, key)
	b := &Beacon{transport: m, client: testDNSClient(cfg, key)}

	if b.registerDual("CHK|b|h|u|linux|amd64", cfg.GetRegistrationPhase()) {
		t.Fatal("registerDual returned true with both transports dead")
	}
	if m.Mode() != transportDNS || !m.Latched() {
		t.Fatalf("after both dead: mode=%q latched=%v, want dns/true", m.Mode(), m.Latched())
	}
}
