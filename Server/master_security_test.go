package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

type masterSecurityTransport func(*http.Request) (*http.Response, error)

func (f masterSecurityTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestMasterRequestsKeepCredentialsOutOfURLs(t *testing.T) {
	const key = "audit-dummy-key"
	const token = "audit-dummy-token"
	mc := &MasterClient{masterURL: "https://audit.invalid", serverID: "audit-server", httpClient: &http.Client{Transport: masterSecurityTransport(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), key) || strings.Contains(r.URL.String(), token) || r.URL.Query().Has("api_key") || r.URL.Query().Has("token") {
			t.Error("credentials remained in request URL")
		}
		if r.Header.Get("X-DNS-Server-API-Key") != key || r.Header.Get("X-Bootstrap-Token") != token {
			t.Error("missing credential headers")
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("{}")), Request: r}, nil
	})}}
	if _, err := mc.doRequest(http.MethodGet, "/audit-only?dns_server_id=audit-server&api_key="+key+"&token="+token, nil); err != nil {
		t.Fatal(err)
	}
}

func TestMasterRequestErrorsDoNotExposeSecrets(t *testing.T) {
	for _, kind := range []string{"network", "response"} {
		t.Run(kind, func(t *testing.T) {
			const marker = "audit-private-marker"
			mc := &MasterClient{masterURL: "https://audit.invalid", httpClient: &http.Client{Transport: masterSecurityTransport(func(r *http.Request) (*http.Response, error) {
				if kind == "network" {
					return nil, errors.New(marker)
				}
				return &http.Response{StatusCode: 401, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(marker)), Request: r}, nil
			})}}
			_, err := mc.doRequest(http.MethodGet, "/audit-only?api_key="+marker, nil)
			if err == nil || strings.Contains(err.Error(), marker) {
				t.Fatalf("unsafe error: %v", err)
			}
		})
	}
}

func TestMasterRequestsDoNotRedirectCredentials(t *testing.T) {
	calls := 0
	mc := &MasterClient{masterURL: "https://audit.invalid", httpClient: &http.Client{Transport: masterSecurityTransport(func(r *http.Request) (*http.Response, error) {
		calls++
		if calls > 1 {
			t.Error("redirect target was contacted")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.invalid/"}}, Body: io.NopCloser(strings.NewReader("")), Request: r}, nil
	})}}
	if _, err := mc.doRequest(http.MethodGet, "/audit-only?api_key=audit-key", nil); err == nil {
		t.Error("redirect response accepted as success")
	}
	if calls != 1 {
		t.Fatalf("requests=%d want 1", calls)
	}
}
