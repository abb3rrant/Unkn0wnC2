package main

import (
	"strings"
	"testing"
)

// The builder must accept every result_transport choice and refuse a bogus one
// before it can reach a beacon build.
func TestValidateClientBuildRequestResultTransport(t *testing.T) {
	valid := []string{"", "auto", "http", "dns", "HTTP", " Dns "}
	for _, rt := range valid {
		req := ClientBuildRequest{
			Transport:       "dual",
			DNSDomains:      []string{"alpha.test"},
			ResultTransport: rt,
		}
		if err := validateClientBuildRequest(req); err != nil {
			t.Errorf("result_transport %q should be valid, got %v", rt, err)
		}
	}

	req := ClientBuildRequest{
		Transport:       "dual",
		DNSDomains:      []string{"alpha.test"},
		ResultTransport: "carrier-pigeon",
	}
	err := validateClientBuildRequest(req)
	if err == nil {
		t.Fatal("result_transport \"carrier-pigeon\" should be rejected")
	}
	if !strings.Contains(err.Error(), "result_transport") {
		t.Errorf("rejection should name the field, got %v", err)
	}
}
