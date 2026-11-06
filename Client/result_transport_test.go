package main

import (
	"errors"
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

// A dual beacon that latched to DNS must still honour result_transport=http:
// the latch narrows check-ins, it does not delete the listener the operator
// explicitly selected for results.
func TestSendResultMessage_ForcesHTTPWhenLatched(t *testing.T) {
	addr, captured := rawHTTPServer(t, "{}")
	cfg := &Config{
		Transport:       "dual",
		HTTPListeners:   []HTTPListener{testListener(addr, nil)},
		ResultTransport: "http",
	}
	manager := newTransportManager(cfg, testKey())
	manager.LatchTo("dns")
	beacon := &Beacon{transport: manager, client: &DNSClient{config: cfg}}

	if _, err := beacon.sendResultMessage("RESULT_COMPLETE|b|T1|1", PhaseConfig{}); err != nil {
		t.Logf("sendResultMessage returned err (response decode expected to be noisy): %v", err)
	}

	select {
	case req := <-captured:
		if req.method != "POST" || !strings.Contains(req.path, "/api/v1/report") {
			t.Errorf("latched result frame = %s %s, want POST /api/v1/report", req.method, req.path)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("result_transport=http did not use the HTTP listener after latching to DNS")
	}
}

// sendResultFrames must size every DATA frame to the injected budget and mark a
// result whose metadata never went out as safely retryable.
func TestSendResultFramesChunking(t *testing.T) {
	result := strings.Repeat("A", 100)
	var frames []string
	send := func(message string) (string, error) {
		frames = append(frames, message)
		return "ACK", nil
	}
	beacon := &Beacon{client: &DNSClient{config: &Config{}}, id: "b1"}
	if err := beacon.sendResultFrames(result, "T1", 30, "dns", send); err != nil {
		t.Fatalf("sendResultFrames() error = %v", err)
	}

	if !strings.HasPrefix(frames[0], "RESULT_META|b1|T1|100|4") {
		t.Fatalf("meta = %q, want 4 chunks", frames[0])
	}
	if frames[len(frames)-1] != "RESULT_COMPLETE|b1|T1|4" {
		t.Fatalf("completion = %q", frames[len(frames)-1])
	}
	dataFrames := 0
	for _, frame := range frames {
		if !strings.HasPrefix(frame, "DATA|") {
			continue
		}
		dataFrames++
		parts := strings.SplitN(frame, "|", 6)
		if len(parts) != 6 || len(parts[5]) > 30 {
			t.Fatalf("DATA frame exceeds the 30-byte budget: %q", frame)
		}
	}
	if dataFrames != 4 {
		t.Fatalf("data frames = %d, want 4", dataFrames)
	}
}

func TestSendResultFramesMetaFailureIsRetryable(t *testing.T) {
	beacon := &Beacon{client: &DNSClient{config: &Config{}}, id: "b1"}
	fail := func(string) (string, error) { return "", errors.New("transport down") }
	err := beacon.sendResultFrames("payload", "T1", 30, "http", fail)
	if err == nil || !errors.Is(err, errResultMetaNotSent) {
		t.Fatalf("error = %v, want errResultMetaNotSent", err)
	}
}

// Auto mode on a dual beacon must not fall back to DNS for a result frame: that
// frame is sized for HTTP. It returns the HTTP error instead so the caller can
// re-chunk for DNS. The DNS client is nil, so a fallback would panic.
func TestSendResultMessage_AutoDoesNotFallbackWithHTTPFrames(t *testing.T) {
	// A closed port: the HTTP send fails immediately.
	cfg := &Config{
		Transport:     "dual",
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
	}
	manager := newTransportManager(cfg, testKey())
	beacon := &Beacon{transport: manager, client: &DNSClient{config: cfg}}

	if _, err := beacon.sendResultMessage("RESULT_META|b|T1|100|1", PhaseConfig{}); err == nil {
		t.Fatal("auto dual with a dead HTTP listener returned success; it must surface the error for a DNS retry")
	}
}
