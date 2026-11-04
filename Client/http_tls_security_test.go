package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Test only TLS peer authentication against an inert local HTTP server.
func TestHTTPTLSPeerAuthentication(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer server.Close()
	sum := sha256.Sum256(server.Certificate().RawSubjectPublicKeyInfo)
	pin := base64.StdEncoding.EncodeToString(sum[:])
	for _, tc := range []struct {
		name, pin, serverName string
		trust                 bool
		wantOK                bool
	}{
		{name: "no pin rejects untrusted certificate"},
		{name: "no pin verifies trusted certificate", trust: true, wantOK: true},
		{name: "no pin verifies hostname", trust: true, serverName: "wrong.invalid"},
		{name: "matching pin accepts self signed certificate", pin: pin, wantOK: true},
		{name: "wrong pin rejects certificate", pin: base64.StdEncoding.EncodeToString(make([]byte, 32))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := &httpTransport{listener: HTTPListener{Host: strings.TrimPrefix(server.URL, "https://"), SPKISHA256: tc.pin}}
			cfg, err := tr.tlsConfig()
			if err != nil {
				t.Fatal(err)
			}
			if tc.trust {
				cfg.RootCAs = x509.NewCertPool()
				cfg.RootCAs.AddCert(server.Certificate())
			}
			if tc.serverName != "" {
				cfg.ServerName = tc.serverName
			}
			transport := &http.Transport{TLSClientConfig: cfg}
			defer transport.CloseIdleConnections()
			client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
			resp, err := client.Get(server.URL)
			if resp != nil {
				resp.Body.Close()
			}
			if (err == nil) != tc.wantOK {
				t.Fatalf("TLS success=%v, want %v (err=%v)", err == nil, tc.wantOK, err)
			}
			if tc.pin == "" && cfg.InsecureSkipVerify {
				t.Error("no-pin TLS must use certificate-chain and hostname verification")
			}
		})
	}
}
