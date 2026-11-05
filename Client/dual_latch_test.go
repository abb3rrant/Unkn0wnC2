package main

import "testing"

// dualModeFromProbes must map the two registration probes onto the mode the
// beacon runs: both answering keeps dual, one answering latches to it, neither
// keeps DNS as best effort.
func TestDualModeFromProbes(t *testing.T) {
	cases := []struct {
		dnsOK, httpOK bool
		want          string
	}{
		{true, true, transportDual},
		{true, false, transportDNS},
		{false, true, transportHTTP},
		{false, false, transportDNS}, // best effort
	}
	for _, c := range cases {
		if got := dualModeFromProbes(c.dnsOK, c.httpOK); got != c.want {
			t.Errorf("dualModeFromProbes(dns=%v, http=%v) = %q, want %q", c.dnsOK, c.httpOK, got, c.want)
		}
	}
}

// LatchTo pins a dual beacon to the working class and is idempotent/no-op for
// dual; Latched reflects it.
func TestTransportManager_LatchTo(t *testing.T) {
	m := newTransportManager(&Config{
		Transport:     "dual",
		DNSDomains:    []string{"a.test"},
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
	}, testKey())
	if m.Mode() != transportDual || m.Latched() {
		t.Fatalf("fresh dual: mode=%q latched=%v", m.Mode(), m.Latched())
	}

	// Latching to dual is a no-op (latching only narrows).
	m.LatchTo(transportDual)
	if m.Latched() || m.Mode() != transportDual {
		t.Fatalf("LatchTo(dual) changed state: mode=%q latched=%v", m.Mode(), m.Latched())
	}

	m.LatchTo(transportHTTP)
	if m.Mode() != transportHTTP || !m.Latched() {
		t.Fatalf("LatchTo(http): mode=%q latched=%v, want http/true", m.Mode(), m.Latched())
	}

	// A second latch to the other class still narrows to what was asked.
	m.LatchTo(transportDNS)
	if m.Mode() != transportDNS || !m.Latched() {
		t.Fatalf("LatchTo(dns): mode=%q latched=%v, want dns/true", m.Mode(), m.Latched())
	}
}
