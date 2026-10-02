package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A profile exists on two sides: the listener reads it from its profile directory or from
// an Archon assignment, and a beacon embeds a copy at build time. Some fields are the
// listener's business alone, and some only work if both sides agree. These tests pin down
// which is which, because getting it wrong produces a beacon that registers and then
// silently receives nothing.

// writeProfileVariant writes a profile file into dir under name and returns it.
func writeProfileVariant(t *testing.T, dir, name string, mutate func(*HTTPProfile)) *HTTPProfile {
	t.Helper()

	profile := DefaultHTTPProfile()
	profile.Name = name
	profile.Scheme = "http"
	profile.BindAddr = "127.0.0.1"
	profile.BindPort = freePort(t)
	if mutate != nil {
		mutate(&profile)
	}
	if err := profile.Validate(); err != nil {
		t.Fatalf("test profile is invalid: %v", err)
	}

	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	return &profile
}

// startListenerFor starts a listener for a profile through a real store, as a deployment
// would, and returns it with its bound address and the store.
//
// The store is returned because reconfiguring a running listener means editing the profile
// file the listener already knows: a listener reads its live profile by name, so a second
// file with a different name is a different listener, not a change to this one.
func startListenerFor(t *testing.T, c2 *C2Manager, dir string, profile *HTTPProfile) (*HTTPListener, string, *HTTPProfileStore) {
	t.Helper()

	store := NewHTTPProfileStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load() error = %v", err)
	}
	if _, ok := store.Get(profile.Name); !ok {
		t.Fatalf("profile %q is not in the store", profile.Name)
	}

	listener, err := NewHTTPListener(profile, store, c2, true)
	if err != nil {
		t.Fatalf("NewHTTPListener() error = %v", err)
	}
	if err := listener.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}
	t.Cleanup(func() { listener.Stop(context.Background()) })

	return listener, "http://" + listener.Addr(), store
}

// rewriteProfileFile overwrites a profile file in place, keeping its name so the running
// listener picks the change up. This is the hot-reload path an operator uses.
func rewriteProfileFile(t *testing.T, dir, name string, profile *HTTPProfile) {
	t.Helper()

	if err := profile.Validate(); err != nil {
		t.Fatalf("replacement profile is invalid: %v", err)
	}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
}

func TestFullyCustomProfile_EnforcesRequestAndShapesResponseHeaders(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	profile := writeProfileVariant(t, dir, "full-headers", func(p *HTTPProfile) {
		p.Auth.Header = "X-Profile-Auth"
		p.RequestHeaders = []HeaderEntry{
			{Name: "Host", Value: "{{host}}"},
			{Name: "X-Campaign", Value: "nightfall"},
			{Name: "Content-Length", Value: "{{content_length}}", Operations: []string{"register", "result"}},
			{Name: "X-Profile-Auth", Value: "{{auth}}"},
		}
		p.ResponseHeaders = []HeaderEntry{
			{Name: "Content-Type", Value: "application/vnd.telemetry+json"},
			{Name: "X-Operation", Value: "{{operation}}"},
			{Name: "X-Status", Value: "{{status}}"},
			{Name: "Cache-Control", Value: "private, max-age=0", Operations: []string{"register"}},
		}
		p.OmitResponseHeaders = []string{"Date"}
	})
	_, baseURL, store := startListenerFor(t, c2, dir, profile)

	makeRequest := func(includeFingerprint bool) *http.Response {
		message := "CHK|customheaders|h|u|linux|amd64|1758500000"
		body, err := encodeHTTPBody(profile.RequestBody, message, key)
		if err != nil {
			t.Fatal(err)
		}
		request, err := http.NewRequest("POST", baseURL+"/api/v1/ping", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set(profile.Auth.Header, signHTTPRequest(key, "POST", "/api/v1/ping", body))
		if includeFingerprint {
			request.Header.Set("X-Campaign", "nightfall")
		}
		response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
		if err != nil {
			t.Fatal(err)
		}
		return response
	}

	missing := makeRequest(false)
	missing.Body.Close()
	if missing.StatusCode != profile.Status.NotFound {
		t.Fatalf("request without custom fingerprint got %d, want %d", missing.StatusCode, profile.Status.NotFound)
	}

	matching := makeRequest(true)
	if matching.StatusCode != profile.Status.OK {
		t.Fatalf("matching request got %d, want %d", matching.StatusCode, profile.Status.OK)
	}
	for name, want := range map[string]string{
		"Content-Type":  "application/vnd.telemetry+json",
		"X-Operation":   "register",
		"X-Status":      strconv.Itoa(profile.Status.OK),
		"Cache-Control": "private, max-age=0",
	} {
		if got := matching.Header.Get(name); got != want {
			t.Errorf("response %s = %q, want %q", name, got, want)
		}
	}
	if got := matching.Header.Get("Date"); got != "" {
		t.Errorf("response carried omitted Date header %q", got)
	}
	matching.Body.Close()

	// Header edits are content changes, not socket changes. Overwrite the same
	// assigned profile, reload it, and prove the next request uses the new value
	// without restarting or rebinding this listener.
	updated := *profile
	updated.ResponseHeaders = []HeaderEntry{
		{Name: "Content-Type", Value: "application/vnd.telemetry+json"},
		{Name: "X-Operation", Value: "rotated-{{operation}}"},
	}
	rewriteProfileFile(t, dir, profile.Name, &updated)
	if applied, rejected := store.Reload(); applied != 1 || rejected != 0 {
		t.Fatalf("Reload() = (%d applied, %d rejected), want (1, 0)", applied, rejected)
	}
	afterReload := makeRequest(true)
	defer afterReload.Body.Close()
	if got := afterReload.Header.Get("X-Operation"); got != "rotated-register" {
		t.Fatalf("hot-reloaded X-Operation = %q, want rotated-register", got)
	}
}

// TestProfileCoupling_URIRotationBreaksUncoordinatedBeacons asserts the coupling that
// matters most in practice: the listener routes by the URIs in *its* profile while the
// beacon requests the paths from *its* embedded copy. Rotating one side alone breaks the
// other, and it fails as a 404 rather than as an obvious error.
func TestProfileCoupling_URIRotationBreaksUncoordinatedBeacons(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	// What the beacon embedded at build time.
	beaconView := DefaultHTTPProfile()
	beaconView.Name = "beacon-view"
	beaconView.Scheme = "http"
	beaconView.BindAddr = "127.0.0.1"
	beaconView.BindPort = freePort(t)

	// The listener is rotated to new URIs without the beacon being rebuilt.
	rotated := writeProfileVariant(t, dir, "rotated", func(p *HTTPProfile) {
		p.URIs = URITable{
			Register: []string{"/v2/ping"},
			Task:     []string{"/v2/sync"},
			Result:   []string{"/v2/report"},
			Ack:      []string{"/v2/ack"},
		}
	})

	_, baseURL, _ := startListenerFor(t, c2, dir, rotated)

	// The beacon's own paths are unchanged...
	status, _ := sendMessage(t, baseURL, &beaconView, key, "POST", "/api/v1/ping",
		"CHK|stalebeacon|h|u|linux|amd64|1758500000")

	// ...and are now unmatched, which is exactly the coupling.
	if status != rotated.Status.NotFound {
		t.Fatalf("a beacon using the old URIs got status %d, want %d: the coupling is not what this test assumes",
			status, rotated.Status.NotFound)
	}

	// The new URIs work for a beacon that knows them.
	if status, response := sendMessage(t, baseURL, rotated, key, "POST", "/v2/ping",
		"CHK|newbeacon|h|u|linux|amd64|1758500001"); status != rotated.Status.OK || response != "ACK" {
		t.Fatalf("a beacon using the new URIs got (%d, %q), want (200, ACK)", status, response)
	}
}

// TestProfileCoupling_OverlappingURIsAllowAZeroDowntimeRotation asserts the recipe for
// rotating URIs safely: because an operation may list several paths, both sides can be
// moved one at a time while both paths are valid.
func TestProfileCoupling_OverlappingURIsAllowAZeroDowntimeRotation(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	// Step 1: the listener accepts old and new at once.
	both := writeProfileVariant(t, dir, "both", func(p *HTTPProfile) {
		p.URIs = URITable{
			Register: []string{"/api/v1/ping", "/v2/ping"},
			Task:     []string{"/api/v1/sync", "/v2/sync"},
			Result:   []string{"/api/v1/report", "/v2/report"},
			Ack:      []string{"/api/v1/ack", "/v2/ack"},
		}
	})

	_, baseURL, store := startListenerFor(t, c2, dir, both)

	// A beacon that has not been updated still works.
	stale := DefaultHTTPProfile()
	stale.Name = "stale"
	stale.Scheme = "http"
	stale.BindAddr = "127.0.0.1"
	stale.BindPort = freePort(t)

	if status, response := sendMessage(t, baseURL, &stale, key, "POST", "/api/v1/ping",
		"CHK|stalebeacon|h|u|linux|amd64|1758500000"); status != both.Status.OK || response != "ACK" {
		t.Fatalf("during the overlap window the old URI failed: (%d, %q)", status, response)
	}

	// Step 2: a beacon that has already been updated also works, without waiting.
	if status, response := sendMessage(t, baseURL, both, key, "POST", "/v2/ping",
		"CHK|newbeacon|h|u|linux|amd64|1758500001"); status != both.Status.OK || response != "ACK" {
		t.Fatalf("during the overlap window the new URI failed: (%d, %q)", status, response)
	}

	// Step 3: the listener drops the old path once every beacon has the new one. This is
	// an edit to the profile it is already serving, picked up by the reload ticker.
	settled := *both
	settled.URIs = URITable{
		Register: []string{"/v2/ping"},
		Task:     []string{"/v2/sync"},
		Result:   []string{"/v2/report"},
		Ack:      []string{"/v2/ack"},
	}
	rewriteProfileFile(t, dir, both.Name, &settled)

	if applied, rejected := store.Reload(); applied != 1 || rejected != 0 {
		t.Fatalf("Reload() = (%d applied, %d rejected), want (1, 0)", applied, rejected)
	}

	if status, response := sendMessage(t, baseURL, &settled, key, "POST", "/v2/ping",
		"CHK|newbeacon|h|u|linux|amd64|1758500002"); status != settled.Status.OK || response != "ACK" {
		t.Fatalf("after the rotation the new URI failed: (%d, %q)", status, response)
	}
	// The same listener, same socket, now refuses the old path.
	if status, _ := sendMessage(t, baseURL, &settled, key, "POST", "/api/v1/ping",
		"CHK|stalebeacon|h|u|linux|amd64|1758500003"); status != settled.Status.NotFound {
		t.Fatalf("the retired URI still routes: status %d", status)
	}
}

// TestProfileCoupling_ResponseCodecDrivesWhatABeaconCanRead pins the behaviour of a body
// codec mismatch, which is subtler than "it stops working".
//
// A listener configured for plain base36 still *processes* an AES-bodied request: the
// base36 wrapper unwinds to the ciphertext, and the pipeline's AES path decrypts it with
// the same key, so the check-in lands. What breaks is the reply — the listener answers in
// its own configured codec, which a beacon expecting AES cannot read. The beacon therefore
// sees a healthy-looking 2xx and an undecodable body.
//
// This is why response_body.encoding is a field that must match the beacon, and why a
// mismatch is worth knowing about rather than discovering as "the beacon registers but
// nothing works".
func TestProfileCoupling_ResponseCodecDrivesWhatABeaconCanRead(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	// The listener answers in plain base36.
	plain := writeProfileVariant(t, dir, "plain", func(p *HTTPProfile) {
		p.RequestBody = BodyCodec{Encoding: codecBase36, Field: "d"}
		p.ResponseBody = BodyCodec{Encoding: codecBase36, Field: "d"}
	})

	_, baseURL, _ := startListenerFor(t, c2, dir, plain)

	// A beacon still encoding with AES-GCM, as an un-updated build would.
	mismatched := DefaultHTTPProfile()
	mismatched.Name = "mismatched"
	mismatched.Scheme = "http"
	mismatched.BindAddr = "127.0.0.1"
	mismatched.BindPort = freePort(t)
	mismatched.RequestBody = BodyCodec{Encoding: codecAESGCMBase36, Field: "d"}
	mismatched.ResponseBody = BodyCodec{Encoding: codecAESGCMBase36, Field: "d"}

	status, raw := sendRawMessage(t, baseURL, &mismatched, key, "POST", "/api/v1/ping",
		"CHK|beacon|h|u|linux|amd64|1758500000")

	if status != plain.Status.OK {
		t.Fatalf("status = %d, want %d: the mismatched request was not processed at all", status, plain.Status.OK)
	}

	// The listener's own codec reads the reply.
	decodedByListener, err := decodeHTTPBody(plain.ResponseBody, raw, key)
	if err != nil {
		t.Fatalf("the reply does not decode with the listener's codec: %v", err)
	}
	if decodedByListener != "ACK" {
		t.Fatalf("listener codec read %q, want ACK", decodedByListener)
	}

	// The beacon's codec does not, which is the breakage.
	if _, err := decodeHTTPBody(mismatched.ResponseBody, raw, key); err == nil {
		t.Fatal("the reply decoded with the beacon's codec too, so a mismatch would be harmless")
	}
}

// sendRawMessage sends a signed request and returns the status with the undecoded body,
// so a test can examine what a mismatched codec actually produced.
func sendRawMessage(t *testing.T, baseURL string, profile *HTTPProfile, key []byte, method, path, message string) (int, []byte) {
	t.Helper()

	body, err := encodeHTTPBody(profile.RequestBody, message, key)
	if err != nil {
		t.Fatalf("failed to encode request: %v", err)
	}

	request, err := http.NewRequest(method, baseURL+path, strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(profile.Auth.Header, signHTTPRequest(key, method, path, body))

	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(request)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer response.Body.Close()

	raw, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, raw
}

// TestProfileCoupling_AuthMismatchIsRejected asserts the third wire-coupled group: the
// signature is verified with the listener's copy of the auth settings.
func TestProfileCoupling_AuthMismatchIsRejected(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	// The listener expects the signature in a different header.
	moved := writeProfileVariant(t, dir, "moved", func(p *HTTPProfile) {
		p.Auth.Header = "X-Request-Signature"
	})

	_, baseURL, _ := startListenerFor(t, c2, dir, moved)

	// A beacon still signing the configured header is not authenticated.
	oldHeader := DefaultHTTPProfile()
	oldHeader.Name = "old-header"
	oldHeader.Scheme = "http"
	oldHeader.BindAddr = "127.0.0.1"
	oldHeader.BindPort = freePort(t)
	oldHeader.Auth.Header = "X-Sig"

	status, _ := sendMessage(t, baseURL, &oldHeader, key, "POST", "/api/v1/ping",
		"CHK|beacon|h|u|linux|amd64|1758500000")
	if status != moved.Status.NotFound {
		t.Fatalf("a stale auth header answered %d, want %d", status, moved.Status.NotFound)
	}

	if status, response := sendMessage(t, baseURL, moved, key, "POST", "/api/v1/ping",
		"CHK|beacon|h|u|linux|amd64|1758500001"); status != moved.Status.OK || response != "ACK" {
		t.Fatalf("a matching beacon got (%d, %q), want (200, ACK)", status, response)
	}
}

// TestProfileSoloFields_ChangeWithoutTouchingBeacons asserts the fields that are the
// listener's business alone: changing them must not affect a beacon that knows nothing
// about the change. This is the half an operator can rotate freely.
func TestProfileSoloFields_ChangeWithoutTouchingBeacons(t *testing.T) {
	c2 := withTestC2Manager(t)
	key := c2.GetEncryptionKey()
	dir := t.TempDir()

	// What the beacon embedded: original status codes, no jitter, its own padding.
	beaconView := DefaultHTTPProfile()
	beaconView.Name = "beacon-view"
	beaconView.Scheme = "http"
	beaconView.BindAddr = "127.0.0.1"
	beaconView.BindPort = freePort(t)
	beaconView.RequestBody = BodyCodec{Encoding: codecAESGCMBase36, Field: "d", PaddingFld: "p", PadMin: 8, PadMax: 24}

	// The listener is reconfigured in ways only it can observe: a tighter skew window, a
	// different response status for success, jitter, and a different padding field it will
	// never read.
	reconfigured := writeProfileVariant(t, dir, "reconfigured", func(p *HTTPProfile) {
		p.RequestBody = BodyCodec{Encoding: codecAESGCMBase36, Field: "d", PaddingFld: "unused", PadMin: 1, PadMax: 2}
		p.ResponseBody = BodyCodec{Encoding: codecAESGCMBase36, Field: "d"}
		p.Auth.MaxSkewSecs = 30
		p.Status.OK = 201
		p.Jitter = ProfileJitter{MinMs: 1, MaxMs: 3}
	})

	_, baseURL, _ := startListenerFor(t, c2, dir, reconfigured)

	status, response := sendMessage(t, baseURL, &beaconView, key, "POST", "/api/v1/ping",
		"CHK|solo|h|u|linux|amd64|1758500000")

	// The beacon only has to see a 2xx; the exact code is the listener's choice.
	if status != 201 {
		t.Fatalf("status = %d, want the listener's configured 201", status)
	}
	// And the response decodes with the beacon's own codec, so padding and status changes
	// are invisible to it.
	if response != "ACK" {
		t.Fatalf("response = %q, want ACK", response)
	}
}
