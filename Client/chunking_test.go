package main

import "testing"

// TestResultChunkSizeHTTPHonoursOperatorBudget pins the behaviour the operator
// knob exists for: on HTTP the chunk is the configured size, not the DNS one.
func TestResultChunkSizeHTTPHonoursOperatorBudget(t *testing.T) {
	cfg := Config{
		Transport:        "http",
		MaxCommandLength: 400,
		DNSDomains:       []string{},
		HTTPExfil:        HTTPExfilConfig{MaxPayload: 65536, MaxBodyBytes: 1048576},
	}
	if got := cfg.ResultChunkSize(); got != 65536 {
		t.Fatalf("HTTP chunk size = %d, want 65536", got)
	}

	// 1 KiB of output must be one request, not thirteen.
	total := (1024 + cfg.ResultChunkSize() - 1) / cfg.ResultChunkSize()
	if total != 1 {
		t.Fatalf("1 KiB produced %d chunks, want 1", total)
	}
}

// TestResultChunkSizeHTTPClampedByBodyLimit keeps a beacon from building chunks
// the listener would reject: base36 expands 5 bytes to 8 characters.
func TestResultChunkSizeHTTPClampedByBodyLimit(t *testing.T) {
	cfg := Config{
		Transport:        "http",
		MaxCommandLength: 400,
		HTTPExfil:        HTTPExfilConfig{MaxPayload: 5000000, MaxBodyBytes: 1000},
	}
	if got, want := cfg.ResultChunkSize(), 625; got != want {
		t.Fatalf("clamped chunk size = %d, want %d", got, want)
	}
}

// TestResultChunkSizeDNSUnchanged guards the DNS path against the new knob: a
// build that says nothing about HTTP keeps the historical sizing.
func TestResultChunkSizeDNSUnchanged(t *testing.T) {
	cfg := Config{
		Transport:          "dns",
		MaxCommandLength:   400,
		DNSDomains:         []string{"alpha.test"},
		DataExfil:          PhaseConfig{QueryType: "TXT", Encrypted: true},
		HTTPExfil:          HTTPExfilConfig{MaxPayload: 65536},
		MaxSubdomainLength: 0,
	}
	got := cfg.ResultChunkSize()
	if got >= 65536 {
		t.Fatalf("DNS chunk size = %d; the HTTP budget leaked into the DNS path", got)
	}
	if got <= 0 || got > 200 {
		t.Fatalf("DNS chunk size = %d, want the historical ~80 byte budget", got)
	}
}

// TestResultBurstPrefersHTTPValues covers the pacing override.
func TestResultBurstPrefersHTTPValues(t *testing.T) {
	cfg := Config{
		Transport:           "http",
		ExfilChunksPerBurst: 10,
		ExfilBurstPauseMs:   5000,
		HTTPExfil:           HTTPExfilConfig{ChunksPerBurst: 4, BurstPauseMs: 250},
	}
	burst, pause := cfg.ResultBurst()
	if burst != 4 || pause != 250 {
		t.Fatalf("burst = (%d,%d), want (4,250)", burst, pause)
	}
}
