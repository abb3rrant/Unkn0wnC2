package main

import (
	"encoding/json"
	"strings"
	"testing"
)

// Runtime transport updates may retune the dual check-in split; nil means keep
// the build-time values, and negative values are rejected.
func TestBuildTransportUpdatePayloadWithWeights(t *testing.T) {
	dns, http := 2, 1
	payload, err := buildTransportUpdatePayloadWithWeights("dns", nil, 0, 0, &dns, &http)
	if err != nil {
		t.Fatalf("buildTransportUpdatePayloadWithWeights: %v", err)
	}
	var doc map[string]interface{}
	if err := json.Unmarshal([]byte(payload), &doc); err != nil {
		t.Fatalf("payload is not JSON: %v", err)
	}
	if doc["dns_weight"] != float64(2) || doc["http_weight"] != float64(1) {
		t.Fatalf("weights not carried: %v", doc)
	}

	plain, err := buildTransportUpdatePayload("dns", nil, 0, 0)
	if err != nil {
		t.Fatalf("buildTransportUpdatePayload: %v", err)
	}
	if strings.Contains(plain, "dns_weight") || strings.Contains(plain, "http_weight") {
		t.Fatalf("weights present when not requested: %s", plain)
	}

	neg := -1
	if _, err := buildTransportUpdatePayloadWithWeights("dns", nil, 0, 0, &neg, nil); err == nil {
		t.Fatal("negative dns_weight was accepted")
	}
}
