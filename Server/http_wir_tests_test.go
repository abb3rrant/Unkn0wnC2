package main

import (
	"net/http/httptest"
	"testing"
)

// WIR-3: the default skew window must be tight. A wide default (300s) lets a
// captured request stay replayable for minutes. The shipped default is 60s.
func TestDefaultProfileReplayWindowIsTight(t *testing.T) {
	if got := DefaultHTTPProfile().Auth.MaxSkewSecs; got != 60 {
		t.Fatalf("DefaultHTTPProfile().Auth.MaxSkewSecs = %d, want 60", got)
	}
}

// The GET signature must reject a tampered query without needing decryption:
// this is the server-side half of WIR-1 exercised at the verifier level.
func TestVerifyHTTPRequestBindsGETQuerySign(t *testing.T) {
	key := generateAESKey("testkey123")
	p := DefaultHTTPProfile()
	p.Auth.Mode = authHMACSHA256
	p.Auth.Header = "X-Sig"
	p.Auth.SigEncoding = "hex"
	p.Auth.MaxSkewSecs = 60

	// A valid signature over target A must not authenticate target B (different
	// query message).
	signA := signHTTPRequest(key, "GET", "/api/v1/sync?d=msgA", nil)
	rB := httptest.NewRequest("GET", "/api/v1/sync?d=msgB", nil)
	rB.Header.Set(p.Auth.Header, signA)
	if err := verifyHTTPRequest(&p, key, rB, nil); err == nil {
		t.Fatal("accepted a signature computed over a different query value")
	}

	// A signature over the actual target must authenticate.
	signB := signHTTPRequest(key, "GET", "/api/v1/sync?d=msgB", nil)
	rB2 := httptest.NewRequest("GET", "/api/v1/sync?d=msgB", nil)
	rB2.Header.Set(p.Auth.Header, signB)
	if err := verifyHTTPRequest(&p, key, rB2, nil); err != nil {
		t.Fatalf("rejected a valid signature over the actual query: %v", err)
	}
}
