package main

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type bootstrapRoundTripper func(*http.Request) (*http.Response, error)

func (f bootstrapRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestFetchBootstrapProfileUsesHeaderAndNoSecretURL(t *testing.T) {
	const secret = "sentinel-bootstrap-secret"
	old := http.DefaultTransport
	http.DefaultTransport = bootstrapRoundTripper(func(r *http.Request) (*http.Response, error) {
		if strings.Contains(r.URL.String(), secret) || r.URL.Query().Get("t") != "" {
			t.Errorf("secret in URL: %s", r.URL)
		}
		if r.Header.Get("X-Bootstrap-Token") != secret {
			t.Errorf("missing token header")
		}
		return &http.Response{StatusCode: 200, Body: ioNopCloser(strings.NewReader(`{"payload":"ok"}`)), Header: make(http.Header), Request: r}, nil
	})
	defer func() { http.DefaultTransport = old }()
	if _, err := fetchBootstrapProfile("http://listener.invalid/_p", secret, ""); err != nil {
		t.Fatal(err)
	}
}

func TestFetchBootstrapProfileRedactsNetworkError(t *testing.T) {
	const secret = "sentinel-bootstrap-secret"
	old := http.DefaultTransport
	http.DefaultTransport = bootstrapRoundTripper(func(r *http.Request) (*http.Response, error) { return nil, errors.New("dial failed for " + secret) })
	defer func() { http.DefaultTransport = old }()
	_, err := fetchBootstrapProfile("http://listener.invalid/_p", secret, "")
	if err == nil || strings.Contains(err.Error(), secret) {
		t.Fatalf("error leaks secret: %v", err)
	}
}

func TestFetchBootstrapProfileDoesNotRedirectCredentials(t *testing.T) {
	const secret = "sentinel-bootstrap-secret"
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Bootstrap-Token") == secret {
			t.Error("credential forwarded")
		}
	}))
	defer target.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, http.StatusFound) }))
	defer first.Close()
	_, err := fetchBootstrapProfile(first.URL, secret, "")
	if err == nil {
		t.Fatal("expected redirect rejection")
	}
}

type nopCloser struct{ *strings.Reader }

func (nopCloser) Close() error                { return nil }
func ioNopCloser(s *strings.Reader) nopCloser { return nopCloser{s} }
