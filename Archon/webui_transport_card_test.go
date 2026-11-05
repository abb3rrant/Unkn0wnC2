package main

import (
	"strings"
	"testing"
)

// The beacon transport card is selection-driven: the operator picks endpoints,
// the mode is derived, and an Active badge reflects real contacts. The old mode
// dropdown and its immediate-apply helpers must be gone.
func TestBeaconTransportCardIsSelectionDriven(t *testing.T) {
	html := readWebFile(t, "beacon.html")

	for _, forbidden := range []string{
		`id="beaconTransportMode"`,
		"applyBeaconHTTPListeners",
		"toggleBeaconDomain",
	} {
		if strings.Contains(html, forbidden) {
			t.Errorf("stale mode-driven control still present: %s", forbidden)
		}
	}

	for _, required := range []string{
		`id="beaconTransportActive"`,
		`id="beaconTransportComputed"`,
		`id="beaconTransportApply"`,
		"function computeTransportMode",
		"function loadTransportActive",
		"function applyBeaconTransport",
		"if (dnsCount > 0 && httpCount > 0) return 'dual';",
		"if (dnsCount > 0) return 'dns';",
		"if (httpCount > 0) return 'http';",
	} {
		if !strings.Contains(html, required) {
			t.Errorf("missing transport-card wiring: %s", required)
		}
	}
}
