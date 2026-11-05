package main

import (
	"strings"
	"testing"
	"time"
)

// A dual beacon normally sends results HTTP-first with DNS as the fallback
// (sendControlMessage). ResultTransport lets the operator override that: "http"
// must force the frame over an HTTP listener even in dual mode, and must not
// silently fall over to DNS on the slow path. The DNS client is deliberately
// nil: if the code fell through to DNS it would panic, which is the test.
func TestSendResultMessage_ForcesHTTP(t *testing.T) {
	addr, captured := rawHTTPServer(t, "{}")
	cfg := &Config{
		Transport:       "dual",
		HTTPListeners:   []HTTPListener{testListener(addr, nil)},
		ResultTransport: "http",
	}
	manager := newTransportManager(cfg, testKey())
	beacon := &Beacon{transport: manager, client: &DNSClient{config: cfg}}

	if _, err := beacon.sendResultMessage("RESULT_COMPLETE|b|T1|1", PhaseConfig{}); err != nil {
		t.Logf("sendResultMessage returned err (response decode expected to be noisy): %v", err)
	}

	select {
	case req := <-captured:
		if req.method != "POST" {
			t.Errorf("result frame method = %s, want POST", req.method)
		}
		if !strings.Contains(req.path, "/api/v1/report") {
			t.Errorf("result frame path = %q, want /api/v1/report", req.path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ResultTransport=http did not send the frame over HTTP (or fell through to DNS and panicked)")
	}
}

// ResultTransport=http on a beacon with no HTTP transport must return a clear
// error, not hang or panic.
func TestSendResultMessage_NoHTTPTransport(t *testing.T) {
	cfg := &Config{Transport: "dns", ResultTransport: "http"}
	manager := newTransportManager(cfg, testKey())
	beacon := &Beacon{transport: manager, client: &DNSClient{config: cfg}}

	_, err := beacon.sendResultMessage("RESULT_COMPLETE|b|T1|1", PhaseConfig{})
	if err == nil {
		t.Fatal("ResultTransport=http with no HTTP transport should error")
	}
	if !strings.Contains(err.Error(), "no HTTP transport") {
		t.Errorf("error should explain the missing HTTP transport, got %v", err)
	}
}
