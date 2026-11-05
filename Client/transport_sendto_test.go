package main

import (
	"testing"
	"time"
)

// SendTo must use exactly the chosen listener and never fall through to another,
// so the endpoint the check-in selector picked is the one that is actually used.
func TestSendTo_HitsChosenListener(t *testing.T) {
	key := testKey()
	addr0, cap0 := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK0", key))
	addr1, cap1 := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK1", key))

	cfg := &Config{
		Transport:     "http",
		HTTPListeners: []HTTPListener{testListener(addr0, nil), testListener(addr1, nil)},
	}
	m := newTransportManager(cfg, key)

	resp, err := m.SendTo(1, "register", "CHK|b|h|u|linux|amd64|12345")
	if err != nil {
		t.Fatalf("SendTo(1) error: %v", err)
	}
	if resp != "ACK1" {
		t.Errorf("SendTo(1) response = %q, want ACK1", resp)
	}

	select {
	case <-cap1:
	case <-time.After(3 * time.Second):
		t.Fatal("SendTo(1) did not reach listener 1")
	}
	select {
	case <-cap0:
		t.Fatal("SendTo(1) also reached listener 0; it must not iterate")
	case <-time.After(300 * time.Millisecond):
		// good: listener 0 untouched
	}

	if _, err := m.SendTo(5, "register", "x"); err == nil {
		t.Fatal("SendTo with out-of-range index should error")
	}
}
