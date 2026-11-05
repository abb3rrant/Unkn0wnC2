package main

import "testing"

// A dual beacon rides HTTP for results, so it must size chunks with the HTTP
// budget; a DNS-latched beacon keeps the small DNS budget.
func TestResultChunkSizeFor_DualUsesHTTPBudget(t *testing.T) {
	c := &Config{
		Transport:          "dual",
		MaxSubdomainLength: 62,
		MaxCommandLength:   400,
		HTTPExfil: HTTPExfilConfig{
			MaxPayload:     60000,
			MaxBodyBytes:   1000000,
			ChunksPerBurst: 4,
			BurstPauseMs:   100,
		},
	}

	if got := c.ResultChunkSizeFor("dual"); got != 60000 {
		t.Errorf("dual chunk size = %d, want 60000 (HTTP budget)", got)
	}
	if got := c.ResultChunkSizeFor("http"); got != 60000 {
		t.Errorf("http chunk size = %d, want 60000", got)
	}
	dns := c.ResultChunkSizeFor("dns")
	if dns >= 60000 || dns < 1 {
		t.Errorf("dns chunk size = %d, want a small DNS budget", dns)
	}

	if burst, pause := c.ResultBurstFor("dual"); burst != 4 || pause != 100 {
		t.Errorf("dual burst = (%d,%d), want (4,100) HTTP values", burst, pause)
	}
}
