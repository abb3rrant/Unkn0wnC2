package main

import "testing"

// TestParseHTTPProfileTask covers the short-form task the beacon receives when an
// operator attaches an HTTP listener.
func TestParseHTTPProfileTask(t *testing.T) {
	url, token, pin, ok := parseHTTPProfileTask("http_profile:https://10.0.0.5:8443/_p|deadbeef|PIN")
	if !ok {
		t.Fatal("valid task rejected")
	}
	if url != "https://10.0.0.5:8443/_p" || token != "deadbeef" || pin != "PIN" {
		t.Fatalf("parsed (%q,%q,%q)", url, token, pin)
	}

	// A plain-HTTP listener has no pin; the task is still valid.
	if url, _, pin, ok := parseHTTPProfileTask("http_profile:http://10.0.0.5:8444/_p|abc"); !ok || pin != "" || url == "" {
		t.Fatalf("pin-less task rejected: ok=%v pin=%q url=%q", ok, pin, url)
	}

	for _, bad := range []string{
		"update_transport:{}",
		"http_profile:",
		"http_profile:not-a-url",
		"http_profile:|token",
	} {
		if _, _, _, ok := parseHTTPProfileTask(bad); ok {
			t.Fatalf("malformed task accepted: %q", bad)
		}
	}
}
