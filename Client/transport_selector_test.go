package main

import (
	"math"
	"testing"
)

// A dual beacon must spread check-ins across the DNS class and the HTTP class
// by the configured weights (default 2:1, DNS favoured), and pick a concrete
// endpoint uniformly within the chosen class.
func TestSelectEndpoint_WeightedDual(t *testing.T) {
	cfg := &Config{
		Transport:         "dual",
		DNSDomains:        []string{"alpha.test", "bravo.test", "charlie.test"},
		HTTPListeners:     []HTTPListener{testListener("127.0.0.1:1", nil), testListener("127.0.0.1:2", nil)},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}
	m := newTransportManager(cfg, testKey())
	if m.dnsEndpoints != 3 {
		t.Fatalf("dnsEndpoints = %d, want 3", m.dnsEndpoints)
	}
	if len(m.transports) != 2 {
		t.Fatalf("http transports = %d, want 2", len(m.transports))
	}

	const draws = 20000
	dnsPicks, httpPicks := 0, 0
	for i := 0; i < draws; i++ {
		kind, idx := m.SelectEndpoint()
		switch kind {
		case "dns":
			if idx < 0 || idx >= 3 {
				t.Fatalf("dns index out of range: %d", idx)
			}
			dnsPicks++
		case "http":
			if idx < 0 || idx >= 2 {
				t.Fatalf("http index out of range: %d", idx)
			}
			httpPicks++
		default:
			t.Fatalf("unknown endpoint kind %q", kind)
		}
	}
	if dnsPicks+httpPicks != draws {
		t.Fatalf("picks %d != draws %d", dnsPicks+httpPicks, draws)
	}

	frac := float64(dnsPicks) / float64(draws)
	// 2:1 with 20k draws: expect ~0.667, allow sampling noise.
	if math.Abs(frac-0.6667) > 0.02 {
		t.Errorf("DNS check-in fraction = %.3f, want ~0.667 (dns=%d http=%d)", frac, dnsPicks, httpPicks)
	}
}

// A single live class takes every pick, regardless of weights.
func TestSelectEndpoint_SingleClass(t *testing.T) {
	// Dual with DNS only.
	dnsOnly := newTransportManager(&Config{
		Transport:         "dual",
		DNSDomains:        []string{"alpha.test", "bravo.test", "charlie.test"},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}, testKey())
	for i := 0; i < 200; i++ {
		kind, idx := dnsOnly.SelectEndpoint()
		if kind != "dns" || idx >= 3 {
			t.Fatalf("dns-only dual picked %s/%d", kind, idx)
		}
	}

	// Dual with HTTP only.
	httpOnly := newTransportManager(&Config{
		Transport:         "dual",
		HTTPListeners:     []HTTPListener{testListener("127.0.0.1:1", nil)},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}, testKey())
	if httpOnly.dnsEndpoints != 0 {
		t.Fatalf("dnsEndpoints = %d, want 0", httpOnly.dnsEndpoints)
	}
	for i := 0; i < 200; i++ {
		kind, idx := httpOnly.SelectEndpoint()
		if kind != "http" || idx != 0 {
			t.Fatalf("http-only dual picked %s/%d", kind, idx)
		}
	}
}

// Single-class modes are forced, and default weights apply when unset.
func TestSelectEndpoint_ForcedModesAndDefaults(t *testing.T) {
	dns := newTransportManager(&Config{
		Transport:  "dns",
		DNSDomains: []string{"a.test", "b.test"},
	}, testKey())
	if kind, _ := dns.SelectEndpoint(); kind != "dns" {
		t.Fatalf("dns mode picked %q", kind)
	}

	httpM := newTransportManager(&Config{
		Transport:     "http",
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
	}, testKey())
	if kind, _ := httpM.SelectEndpoint(); kind != "http" {
		t.Fatalf("http mode picked %q", kind)
	}

	// Dual, zero weights -> default 2:1, still roughly two thirds DNS.
	def := newTransportManager(&Config{
		Transport:     "dual",
		DNSDomains:    []string{"a.test", "b.test", "c.test"},
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil), testListener("127.0.0.1:2", nil)},
	}, testKey())
	dnsN := 0
	const draws = 10000
	for i := 0; i < draws; i++ {
		if kind, _ := def.SelectEndpoint(); kind == "dns" {
			dnsN++
		}
	}
	if frac := float64(dnsN) / float64(draws); math.Abs(frac-0.6667) > 0.03 {
		t.Errorf("default-weight DNS fraction = %.3f, want ~0.667", frac)
	}
}
