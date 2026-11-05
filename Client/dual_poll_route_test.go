package main

import (
	"testing"
	"time"
)

// In dual mode, a completed registration (stage>=3) makes each check-in a POLL
// that must go to exactly one endpoint chosen by SelectEndpoint. With HTTP as
// the only available class (no DNS domains), the poll must ride HTTP.
func TestCheckIn_DualPollRoutesToHTTP(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	cfg := &Config{
		Transport:     "dual",
		HTTPListeners: []HTTPListener{testListener(addr, nil)},
		QueryType:     "TXT",
		Timeout:       1,
		RetryAttempts: 1,
	}
	m := newTransportManager(cfg, key)
	b := &Beacon{transport: m, client: testDNSClient(cfg, key), id: "beacon-x"}
	b.regStage.Store(3)

	resp, err := b.checkIn()
	if err != nil {
		t.Fatalf("checkIn poll error: %v", err)
	}
	if resp != "ACK" {
		t.Errorf("poll response = %q, want ACK", resp)
	}

	select {
	case req := <-captured:
		if req.method != "GET" {
			t.Errorf("dual poll method = %s, want GET (task op)", req.method)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("dual poll did not go over the HTTP endpoint")
	}
}

// A DNS-chosen dual poll must NOT touch HTTP. With DNS weights forced high and
// an unresolvable domain, checkIn errors on DNS and never sends an HTTP request.
func TestCheckIn_DualPollStaysOnDNSWhenChosen(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	cfg := &Config{
		Transport:         "dual",
		DNSDomains:        []string{"nope.invalid"},
		HTTPListeners:     []HTTPListener{testListener(addr, nil)},
		QueryType:         "TXT",
		Timeout:           1,
		RetryAttempts:     1,
		CheckinDNSWeight:  1000, // force the DNS class
		CheckinHTTPWeight: 0,
	}
	m := newTransportManager(cfg, key)
	b := &Beacon{transport: m, client: testDNSClient(cfg, key), id: "beacon-y"}
	b.regStage.Store(3)

	// The DNS lookup for nope.invalid fails, so checkIn returns an error; the
	// point is that it did not silently fall over to HTTP.
	_, _ = b.checkIn()

	select {
	case <-captured:
		t.Fatal("DNS-chosen dual poll fell over to HTTP")
	case <-time.After(300 * time.Millisecond):
		// good: HTTP untouched
	}
}
