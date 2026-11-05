package main

import (
	"encoding/json"
	"testing"
)

// After update_domains, a beacon that started with no domains must be able to
// select the DNS class (the endpoint count is refreshed, not stale).
func TestRefreshDomainsEnablesDNSAfterUpdate(t *testing.T) {
	cfg := &Config{
		Transport:         "dual",
		HTTPListeners:     []HTTPListener{testListener("127.0.0.1:1", nil)},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}
	m := newTransportManager(cfg, testKey())
	if m.dnsEndpoints != 0 {
		t.Fatalf("precondition: dnsEndpoints=%d, want 0", m.dnsEndpoints)
	}

	m.RefreshDomains(3)
	if m.dnsEndpoints != 3 {
		t.Fatalf("dnsEndpoints=%d after RefreshDomains(3), want 3", m.dnsEndpoints)
	}

	dnsPicks := 0
	for i := 0; i < 5000; i++ {
		if kind, _ := m.SelectEndpoint(); kind == "dns" {
			dnsPicks++
		}
	}
	if dnsPicks == 0 {
		t.Fatal("DNS never selected after domains were added")
	}
}

// Switching to dns with no configured domains must be refused, keeping the
// working configuration; once domains exist it is accepted.
func TestApplyUpdate_DNSRejectedWithoutDomains(t *testing.T) {
	cfg := &Config{
		Transport:     "http",
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
	}
	m := newTransportManager(cfg, testKey())

	if err := m.ApplyUpdate(`{"mode":"dns"}`); err == nil {
		t.Fatal("ApplyUpdate(dns) accepted with zero domains")
	}
	if m.Mode() != transportHTTP {
		t.Fatalf("mode changed to %q after a rejected update", m.Mode())
	}

	m.RefreshDomains(2)
	if err := m.ApplyUpdate(`{"mode":"dns"}`); err != nil {
		t.Fatalf("ApplyUpdate(dns) with domains: %v", err)
	}
	if m.Mode() != transportDNS {
		t.Fatalf("mode=%q, want dns", m.Mode())
	}
}

// A runtime update clears the startup latch and can retune the split.
func TestApplyUpdate_ClearsLatchAndSetsWeights(t *testing.T) {
	cfg := &Config{
		Transport:         "dual",
		DNSDomains:        []string{"a.test", "b.test"},
		HTTPListeners:     []HTTPListener{testListener("127.0.0.1:1", nil)},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}
	m := newTransportManager(cfg, testKey())
	m.LatchTo(transportDNS)
	if !m.Latched() {
		t.Fatal("precondition: expected latched")
	}

	listener := testListener("127.0.0.1:1", nil)
	payload, _ := json.Marshal(map[string]interface{}{
		"mode":        "dual",
		"listeners":   []HTTPListener{listener},
		"dns_weight":  1,
		"http_weight": 5,
	})
	if err := m.ApplyUpdate(string(payload)); err != nil {
		t.Fatalf("ApplyUpdate: %v", err)
	}
	if m.Latched() {
		t.Fatal("latched still true after an operator update")
	}
	if m.Mode() != transportDual || m.dnsWeight != 1 || m.httpWeight != 5 {
		t.Fatalf("mode=%q weights=%d:%d, want dual 1:5", m.Mode(), m.dnsWeight, m.httpWeight)
	}
}

// handleUpdateDomains must refresh the selector, not just the DNS client config.
func TestHandleUpdateDomainsRefreshesSelector(t *testing.T) {
	cfg := &Config{
		Transport:         "dual",
		HTTPListeners:     []HTTPListener{testListener("127.0.0.1:1", nil)},
		CheckinDNSWeight:  2,
		CheckinHTTPWeight: 1,
	}
	m := newTransportManager(cfg, testKey())
	b := &Beacon{transport: m, client: testDNSClient(cfg, testKey())}

	b.handleUpdateDomains(`["alpha.test","bravo.test","charlie.test"]`)

	if m.dnsEndpoints != 3 {
		t.Fatalf("dnsEndpoints=%d after handleUpdateDomains, want 3", m.dnsEndpoints)
	}
	if len(cfg.DNSDomains) != 3 {
		t.Fatalf("cfg.DNSDomains=%v, want 3 domains", cfg.DNSDomains)
	}
}
