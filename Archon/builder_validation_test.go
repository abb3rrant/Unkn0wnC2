package main

import "testing"

func TestValidateClientBuildRequestRequiresListeners(t *testing.T) {
	listener := HTTPListenerSpec{Name: "default", Scheme: "https", Host: "c2.example.com:443"}
	domain := []string{"alpha.test"}

	cases := []struct {
		name    string
		req     ClientBuildRequest
		wantErr bool
	}{
		{"dns with domain", ClientBuildRequest{Transport: "dns", DNSDomains: domain}, false},
		{"dns without domain", ClientBuildRequest{Transport: "dns"}, true},
		{"http without listener", ClientBuildRequest{Transport: "http"}, true},
		{"http with listener", ClientBuildRequest{Transport: "http", HTTPListeners: []HTTPListenerSpec{listener}}, false},
		{"dual without listener", ClientBuildRequest{Transport: "dual", DNSDomains: domain}, true},
		{"dual with listener", ClientBuildRequest{Transport: "dual", DNSDomains: domain, HTTPListeners: []HTTPListenerSpec{listener}}, false},
	}

	for _, tc := range cases {
		err := validateClientBuildRequest(tc.req)
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}
