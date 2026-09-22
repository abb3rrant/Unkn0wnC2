package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Body codecs
// =============================================================================

// TestHTTPBodyCodec_RoundTrip covers every selectable encoding, including the
// padding path, so a profile cannot pick a codec the listener mishandles.
func TestHTTPBodyCodec_RoundTrip(t *testing.T) {
	key := generateAESKey("codec-test-key")
	message := "TASK|abc123|whoami"

	for _, encoding := range []string{codecRaw, codecBase64, codecBase36, codecAESGCMBase64, codecAESGCMBase36} {
		t.Run(encoding, func(t *testing.T) {
			codec := BodyCodec{
				Encoding:   encoding,
				Field:      "d",
				PaddingFld: "p",
				PadMin:     8,
				PadMax:     24,
			}

			body, err := encodeHTTPBody(codec, message, key)
			if err != nil {
				t.Fatalf("encodeHTTPBody() error = %v", err)
			}

			// An encrypted body must not contain the plaintext.
			if strings.HasPrefix(encoding, "aes-gcm") && strings.Contains(string(body), "whoami") {
				t.Fatalf("encrypted body leaked plaintext: %s", body)
			}

			decoded, err := decodeHTTPBody(codec, body, key)
			if err != nil {
				t.Fatalf("decodeHTTPBody() error = %v", err)
			}
			if decoded != message {
				t.Fatalf("round trip = %q, want %q", decoded, message)
			}

			// Padding must appear as the declared field for non-raw codecs.
			if encoding != codecRaw {
				var envelope map[string]string
				if err := json.Unmarshal(body, &envelope); err != nil {
					t.Fatalf("body is not JSON: %v", err)
				}
				if _, ok := envelope["p"]; !ok {
					t.Errorf("body has no padding field: %s", body)
				}
				if padding := envelope["p"]; len(padding) < 8 || len(padding) > 24 {
					t.Errorf("padding length %d outside [8,24]", len(padding))
				}
			}
		})
	}
}

// TestHTTPBodyCodec_WrongKeyFails asserts an encrypted body from one key cannot
// be read with another, which is the property the auth relies on.
func TestHTTPBodyCodec_WrongKeyFails(t *testing.T) {
	codec := BodyCodec{Encoding: codecAESGCMBase36, Field: "d"}

	body, err := encodeHTTPBody(codec, "POLL|beacon1", generateAESKey("key-a"))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := decodeHTTPBody(codec, body, generateAESKey("key-b")); err == nil {
		t.Fatal("decodeHTTPBody() with the wrong key succeeded, want failure")
	}
}

// TestHTTPBodyCodec_MissingFieldRejected asserts a well-formed JSON body that
// simply lacks the payload field is rejected rather than treated as empty.
func TestHTTPBodyCodec_MissingFieldRejected(t *testing.T) {
	codec := BodyCodec{Encoding: codecBase64, Field: "d"}
	if _, err := decodeHTTPBody(codec, []byte(`{"other":"AAAA"}`), nil); err == nil {
		t.Fatal("decodeHTTPBody() accepted a body without the payload field")
	}
}

// TestHTTPBodyCodec_PaddingRandomized asserts padding actually varies, since a
// constant length would defeat the point of enabling it.
func TestHTTPBodyCodec_PaddingRandomized(t *testing.T) {
	codec := BodyCodec{Encoding: codecAESGCMBase36, Field: "d", PaddingFld: "p", PadMin: 0, PadMax: 64}
	key := generateAESKey("pad-key")

	lengths := make(map[int]bool)
	for i := 0; i < 24; i++ {
		body, err := encodeHTTPBody(codec, "ACK", key)
		if err != nil {
			t.Fatal(err)
		}
		lengths[len(body)] = true
	}
	if len(lengths) < 2 {
		t.Fatalf("padding produced %d distinct body lengths over 24 encodings, want variation", len(lengths))
	}
}

// =============================================================================
// Request authentication
// =============================================================================

// TestVerifyHTTPRequest_HMAC covers the signing contract: a valid signature
// passes, and every tamper attempt fails closed.
func TestVerifyHTTPRequest_HMAC(t *testing.T) {
	key := generateAESKey("auth-key")
	profile := DefaultHTTPProfile()
	profile.Name = "auth"

	body := []byte(`{"d":"abc"}`)
	newRequest := func(signed string, mutate func(*http.Request)) *http.Request {
		r := &http.Request{
			Method: "POST",
			URL:    mustParseURL(t, "/api/v1/ping"),
			Header: http.Header{},
		}
		if signed != "" {
			r.Header.Set(profile.Auth.Header, signed)
		}
		if mutate != nil {
			mutate(r)
		}
		return r
	}

	t.Run("valid signature", func(t *testing.T) {
		signed := signHTTPRequest(key, "POST", "/api/v1/ping", body)
		if err := verifyHTTPRequest(&profile, key, newRequest(signed, nil), body); err != nil {
			t.Fatalf("verifyHTTPRequest() = %v, want nil", err)
		}
	})

	t.Run("missing header", func(t *testing.T) {
		if err := verifyHTTPRequest(&profile, key, newRequest("", nil), body); err == nil {
			t.Fatal("accepted a request with no signature")
		}
	})

	t.Run("tampered body", func(t *testing.T) {
		signed := signHTTPRequest(key, "POST", "/api/v1/ping", body)
		tampered := []byte(`{"d":"xyz"}`)
		if err := verifyHTTPRequest(&profile, key, newRequest(signed, nil), tampered); err == nil {
			t.Fatal("accepted a signature that does not cover the body")
		}
	})

	t.Run("wrong path", func(t *testing.T) {
		signed := signHTTPRequest(key, "POST", "/api/v1/ping", body)
		r := newRequest(signed, func(r *http.Request) { r.URL = mustParseURL(t, "/api/v1/report") })
		if err := verifyHTTPRequest(&profile, key, r, body); err == nil {
			t.Fatal("accepted a signature bound to a different path")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		signed := signHTTPRequest(generateAESKey("other-key"), "POST", "/api/v1/ping", body)
		if err := verifyHTTPRequest(&profile, key, newRequest(signed, nil), body); err == nil {
			t.Fatal("accepted a signature from a different key")
		}
	})

	t.Run("stale timestamp", func(t *testing.T) {
		stale := fmt.Sprintf("%d.%s", time.Now().Add(-2*time.Hour).Unix(), strings.Repeat("ab", 32))
		if err := verifyHTTPRequest(&profile, key, newRequest(stale, nil), body); err == nil {
			t.Fatal("accepted a replay outside the tolerance window")
		}
	})

	t.Run("malformed header", func(t *testing.T) {
		if err := verifyHTTPRequest(&profile, key, newRequest("not-a-timestamp", nil), body); err == nil {
			t.Fatal("accepted a malformed signature header")
		}
	})

	t.Run("auth none bypasses", func(t *testing.T) {
		open := DefaultHTTPProfile()
		open.Auth.Mode = authNone
		if err := verifyHTTPRequest(&open, key, newRequest("", nil), body); err != nil {
			t.Fatalf("auth mode none rejected a request: %v", err)
		}
	})
}

// =============================================================================
// Rate limiting
// =============================================================================

// TestHTTPRateLimiter_BurstThenBlock asserts a client gets its burst, is then
// throttled, and refills over time while other clients stay unaffected.
func TestHTTPRateLimiter_BurstThenBlock(t *testing.T) {
	limiter := newHTTPRateLimiter()
	current := time.Now()
	limiter.now = func() time.Time { return current }

	allowed := 0
	for i := 0; i < int(httpRateBurst)+10; i++ {
		if limiter.allow("10.0.0.1") {
			allowed++
		}
	}
	if allowed != int(httpRateBurst) {
		t.Fatalf("allowed %d requests, want the burst of %d", allowed, int(httpRateBurst))
	}

	// A different client is unaffected by the first client's exhaustion.
	if !limiter.allow("10.0.0.2") {
		t.Fatal("a fresh client was throttled by another client's usage")
	}

	// After enough time for one token, the throttled client is served again.
	current = current.Add(time.Second)
	if !limiter.allow("10.0.0.1") {
		t.Fatal("client was not refilled after waiting")
	}
}

// TestHTTPRateLimiter_PrunesIdleClients asserts the map does not grow forever.
func TestHTTPRateLimiter_PrunesIdleClients(t *testing.T) {
	limiter := newHTTPRateLimiter()
	current := time.Now()
	limiter.now = func() time.Time { return current }

	limiter.allow("192.0.2.1")
	current = current.Add(httpRateIdleTTL + time.Minute)
	limiter.allow("192.0.2.2")

	limiter.mu.Lock()
	count := len(limiter.buckets)
	limiter.mu.Unlock()

	if count != 1 {
		t.Fatalf("bucket map holds %d entries after pruning, want 1", count)
	}
}

// =============================================================================
// Listener end to end
// =============================================================================

// freePort returns a port that was free a moment ago. The listener cannot bind
// port 0 because a profile with bind_port 0 means "use the default".
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to find a free port: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// newTestListener writes a profile into a temporary directory, loads it through
// a real store, and starts a listener. Using the store (rather than injecting a
// profile) exercises hot-reload lookup on every request.
func newTestListener(t *testing.T, c2 *C2Manager, mutate func(*HTTPProfile)) (*HTTPListener, *HTTPProfile) {
	t.Helper()

	dir := t.TempDir()
	profile := DefaultHTTPProfile()
	profile.Name = "test"
	profile.Scheme = "http"
	profile.BindAddr = "127.0.0.1"
	profile.BindPort = freePort(t)
	profile.Status.OK = 200
	profile.Status.Empty = 204
	profile.Status.NotFound = 404
	profile.Auth.Mode = authHMACSHA256
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
	if err := os.WriteFile(filepath.Join(dir, "test.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}

	store := NewHTTPProfileStore(dir)
	if err := store.Load(); err != nil {
		t.Fatalf("store.Load() error = %v", err)
	}

	listener, err := NewHTTPListener(&profile, store, c2, true)
	if err != nil {
		t.Fatalf("NewHTTPListener() error = %v", err)
	}
	if err := listener.Start(); err != nil {
		t.Fatalf("Start() error = %v", err)
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		listener.Stop(ctx)
	})

	return listener, &profile
}

// sendMessage posts a signed protocol message to a listener and decodes the
// response body with the profile's codec.
func sendMessage(t *testing.T, baseURL string, profile *HTTPProfile, key []byte, method, path, message string) (int, string) {
	t.Helper()

	var body []byte
	var err error
	if message != "" {
		body, err = encodeHTTPBody(profile.RequestBody, message, key)
		if err != nil {
			t.Fatalf("failed to encode request: %v", err)
		}
	}

	url := baseURL + path
	var reader io.Reader
	if len(body) > 0 {
		reader = strings.NewReader(string(body))
	}

	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if len(body) > 0 {
		req.Header.Set("Content-Type", "application/json")
	}
	// The signature covers the path only; the listener verifies against
	// r.URL.Path, so a query string must not be included.
	signPath := path
	if index := strings.Index(signPath, "?"); index >= 0 {
		signPath = signPath[:index]
	}
	req.Header.Set(profile.Auth.Header, signHTTPRequest(key, method, signPath, body))

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("request to %s failed: %v", url, err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 {
		return resp.StatusCode, ""
	}

	decoded, err := decodeHTTPBody(profile.ResponseBody, raw, key)
	if err != nil {
		t.Fatalf("failed to decode response %q: %v", raw, err)
	}
	return resp.StatusCode, decoded
}

// TestHTTPListener_RejectsNonMatchingRequests asserts the scanner-facing shape:
// unknown paths and bad signatures are indistinguishable and never reach C2.
func TestHTTPListener_RejectsNonMatchingRequests(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	baseURL := "http://" + listener.Addr()
	key := c2.GetEncryptionKey()

	t.Run("unknown path", func(t *testing.T) {
		status, body := sendMessage(t, baseURL, profile, key, "GET", "/not/a/route", "POLL|beacon1")
		if status != profile.Status.NotFound {
			t.Errorf("status = %d, want %d", status, profile.Status.NotFound)
		}
		if body != "" {
			t.Errorf("body = %q, want empty", body)
		}
	})

	t.Run("wrong method for a known path", func(t *testing.T) {
		status, _ := sendMessage(t, baseURL, profile, key, "GET", "/api/v1/ping", "CHK|b|h|u|linux|amd64|1758500000")
		if status != profile.Status.NotFound {
			t.Errorf("status = %d, want %d", status, profile.Status.NotFound)
		}
	})

	t.Run("unsigned request", func(t *testing.T) {
		body, _ := encodeHTTPBody(profile.RequestBody, "POLL|beacon1", key)
		req, err := http.NewRequest("GET", baseURL+"/api/v1/sync?d=x", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != profile.Status.NotFound {
			t.Errorf("status = %d, want %d (auth failure must look like a missing endpoint)",
				resp.StatusCode, profile.Status.NotFound)
		}
	})

	// No probe may have created beacon state.
	if beacons := c2.GetBeacons(); len(beacons) != 0 {
		t.Fatalf("rejected probes created %d beacons, want 0", len(beacons))
	}
}

// TestHTTPListener_RegisterAndTask drives the real protocol end to end over a
// real socket: register a beacon, queue a task, pull it over HTTP.
func TestHTTPListener_RegisterAndTask(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	baseURL := "http://" + listener.Addr()
	key := c2.GetEncryptionKey()

	const beaconID = "httpbeacon"
	const taskID = "T1001"

	// 1. Register.
	status, response := sendMessage(t, baseURL, profile, key, "POST", "/api/v1/ping",
		"CHK|"+beaconID+"|host1|user1|linux|amd64|1758500000")
	if status != profile.Status.OK {
		t.Fatalf("register status = %d, want %d", status, profile.Status.OK)
	}
	if response != "ACK" {
		t.Fatalf("register response = %q, want ACK", response)
	}

	beacons := c2.GetBeacons()
	if len(beacons) != 1 || beacons[0].ID != beaconID {
		t.Fatalf("beacons = %+v, want exactly %q", beacons, beaconID)
	}

	// 2. Poll with nothing queued.
	status, response = sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=ignored", "POLL|"+beaconID+"|1758500001")
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("empty poll = (%d, %q), want (200, ACK)", status, response)
	}

	// 3. Queue a task and pull it over HTTP. This is the delivery path dual mode
	// relies on, so it must actually consume the task, not peek at it.
	c2.AddTaskFromMaster(taskID, beaconID, "whoami")

	status, response = sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=ignored", "POLL|"+beaconID+"|1758500002")
	if status != profile.Status.OK {
		t.Fatalf("task poll status = %d, want %d", status, profile.Status.OK)
	}
	if !strings.HasPrefix(response, "TASK|") {
		t.Fatalf("task poll response = %q, want a TASK| message", response)
	}
	if !strings.Contains(response, taskID) || !strings.Contains(response, "whoami") {
		t.Fatalf("task poll response = %q, want it to carry %s and the command", response, taskID)
	}

	// 4. Until RESULT_META confirms receipt the task stays queued and is
	// re-delivered — that is the designed recovery for a lost response, matched
	// on the DNS transport, so assert it rather than forbidding it.
	_, response = sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=ignored", "POLL|"+beaconID+"|1758500003")
	if !strings.Contains(response, taskID) {
		t.Fatalf("unconfirmed task %s was not re-delivered: %q", taskID, response)
	}

	// 5. Once the beacon confirms receipt with RESULT_META, the task leaves the
	// queue and is never handed out again.
	status, response = sendMessage(t, baseURL, profile, key, "POST", "/api/v1/report",
		fmt.Sprintf("RESULT_META|%s|%s|12|1|1758500004", beaconID, taskID))
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("RESULT_META = (%d, %q), want (200, ACK)", status, response)
	}

	_, response = sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=ignored", "POLL|"+beaconID+"|1758500005")
	if strings.Contains(response, taskID) {
		t.Fatalf("confirmed task %s was delivered again: %q", taskID, response)
	}
}

// TestHTTPListener_ResultRoundTrip submits a result over HTTP and asserts the
// task completes, exercising the shared result/chunk path.
func TestHTTPListener_ResultRoundTrip(t *testing.T) {
	c2 := NewC2Manager(false, "listener-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	baseURL := "http://" + listener.Addr()
	key := c2.GetEncryptionKey()

	const beaconID = "resbeacon"
	const taskID = "T2002"
	sendMessage(t, baseURL, profile, key, "POST", "/api/v1/ping",
		"CHK|"+beaconID+"|host1|user1|linux|amd64|1758500000")

	c2.AddTaskFromMaster(taskID, beaconID, "id")
	_, delivered := sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=x", "POLL|"+beaconID+"|1758500001")
	if !strings.Contains(delivered, taskID) {
		t.Fatalf("task was not delivered: %q", delivered)
	}

	// RESULT_META announces one chunk: RESULT_META|id|taskID|totalSize|chunks|ts
	status, response := sendMessage(t, baseURL, profile, key, "POST", "/api/v1/report",
		fmt.Sprintf("RESULT_META|%s|%s|12|1|1758500002", beaconID, taskID))
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("RESULT_META = (%d, %q), want (200, ACK)", status, response)
	}

	// DATA carries it: DATA|id|taskID|chunkIndex|totalChunks|chunkData|ts
	// The chunk payload is base64 by protocol convention; chunkIndex is 1-based.
	chunk := "dWlkPTEwMDA="
	status, response = sendMessage(t, baseURL, profile, key, "POST", "/api/v1/report",
		fmt.Sprintf("DATA|%s|%s|1|1|%s|1758500003", beaconID, taskID, chunk))
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("DATA = (%d, %q), want (200, ACK)", status, response)
	}

	// RESULT_COMPLETE closes it.
	status, response = sendMessage(t, baseURL, profile, key, "POST", "/api/v1/report",
		fmt.Sprintf("RESULT_COMPLETE|%s|%s|1|1758500004", beaconID, taskID))
	if status != profile.Status.OK || response != "ACK" {
		t.Fatalf("RESULT_COMPLETE = (%d, %q), want (200, ACK)", status, response)
	}

	c2.mutex.RLock()
	task, exists := c2.tasks[taskID]
	c2.mutex.RUnlock()
	if !exists {
		t.Fatalf("task %s vanished", taskID)
	}
	if task.Status != "completed" {
		t.Fatalf("task status = %q, want completed", task.Status)
	}
}

// TestHTTPListener_HTTPSPinMismatchFailsAtConstruction asserts a listener that
// would serve a certificate no beacon pins refuses to start, rather than
// appearing healthy while every beacon fails.
func TestHTTPListener_HTTPSPinMismatchFailsAtConstruction(t *testing.T) {
	dir := t.TempDir()

	pinnedCert, _, pinnedSPKI, err := GenerateListenerCert("pinned", dir, "cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	servedCert, servedKey, servedSPKI, err := GenerateListenerCert("served", dir, "cdn.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if pinnedSPKI == servedSPKI {
		t.Fatal("two generated certificates share an SPKI; the test cannot distinguish them")
	}

	c2 := NewC2Manager(false, "tls-key", StagerJitter{}, ":memory:", "example.com")
	store := NewHTTPProfileStore(dir)

	newProfile := func(certFile, keyFile, pin string) *HTTPProfile {
		p := DefaultHTTPProfile()
		p.Name = "tls"
		p.Scheme = "https"
		p.BindAddr = "127.0.0.1"
		p.BindPort = freePort(t)
		p.TLS.CertFile = certFile
		p.TLS.KeyFile = keyFile
		p.TLS.SPKISHA256 = pin
		return &p
	}

	t.Run("pin does not match the served certificate", func(t *testing.T) {
		// A valid key pair, but the profile pins the other certificate.
		if _, err := NewHTTPListener(newProfile(servedCert, servedKey, pinnedSPKI), store, c2, false); err == nil {
			t.Fatal("NewHTTPListener() accepted a listener whose SPKI does not match its pin")
		}
	})

	t.Run("certificate and key do not belong together", func(t *testing.T) {
		if _, err := NewHTTPListener(newProfile(pinnedCert, servedKey, servedSPKI), store, c2, false); err == nil {
			t.Fatal("NewHTTPListener() accepted a mismatched certificate/key pair")
		}
	})

	t.Run("matching pin is accepted", func(t *testing.T) {
		listener, err := NewHTTPListener(newProfile(servedCert, servedKey, servedSPKI), store, c2, false)
		if err != nil {
			t.Fatalf("NewHTTPListener() error = %v, want nil for a matching pin", err)
		}
		if listener == nil {
			t.Fatal("NewHTTPListener() returned a nil listener")
		}
	})
}

// TestHTTPListener_HotReloadChangesRouting asserts a rotated URI on disk takes
// effect on the next request without restarting the listener.
func TestHTTPListener_HotReloadChangesRouting(t *testing.T) {
	c2 := NewC2Manager(false, "reload-key", StagerJitter{}, ":memory:", "example.com")
	listener, profile := newTestListener(t, c2, nil)
	baseURL := "http://" + listener.Addr()
	key := c2.GetEncryptionKey()

	if status, _ := sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=x", "POLL|b|1"); status == profile.Status.NotFound {
		t.Fatalf("configured task URI /api/v1/sync was rejected")
	}

	// Rotate the task URI in the profile file the store watches.
	profile.URIs.Task = []string{"/assets/telemetry"}
	raw, err := json.Marshal(profile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(listener.store.Dir(), "test.json"), raw, 0644); err != nil {
		t.Fatal(err)
	}
	applied, rejected := listener.store.Reload()
	if applied != 1 || rejected != 0 {
		t.Fatalf("Reload() = (%d applied, %d rejected), want (1, 0)", applied, rejected)
	}

	// The new URI works and the old one is gone.
	if status, _ := sendMessage(t, baseURL, profile, key, "GET", "/assets/telemetry?d=x", "POLL|b|1"); status == profile.Status.NotFound {
		t.Fatalf("rotated task URI /assets/telemetry was rejected")
	}
	if status, _ := sendMessage(t, baseURL, profile, key, "GET", "/api/v1/sync?d=x", "POLL|b|1"); status != profile.Status.NotFound {
		t.Fatalf("retired task URI /api/v1/sync still routed (status %d)", status)
	}
}

// TestC2Manager_RejectsImplausibleChunkCount guards a memory-exhaustion path
// reachable without the C2 key: RESULT_META and DATA take a chunk count off the
// wire and size an allocation with it. On the unencrypted (plain base36) path an
// attacker needs no key to reach this code, so an absurd count must be rejected
// rather than allocated.
func TestC2Manager_RejectsImplausibleChunkCount(t *testing.T) {
	c2 := NewC2Manager(false, "bound-key", StagerJitter{}, ":memory:", "example.com")

	// A plain-base36 message, i.e. what an unencrypted beacon (or anyone able to
	// craft one) can send with no key at all.
	messages := []string{
		// totalChunks omitted, so the trailing timestamp parses into that slot.
		"RESULT_META|beacon1|T1|12|1758500000",
		// Explicitly absurd chunk count.
		"RESULT_META|beacon1|T1|12|2000000000|1758500000",
		"DATA|beacon1|T1|1|2000000000|ZGF0YQ==|1758500000",
	}

	for _, message := range messages {
		qname := base36EncodeString(message) + ".example.com"

		// The call must return promptly with isC2=false instead of allocating.
		response, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
		if isC2 {
			t.Errorf("message %q was accepted (response %q), want rejection", message, response)
		}

		c2.mutex.RLock()
		expected := len(c2.expectedResults)
		c2.mutex.RUnlock()
		if expected != 0 {
			t.Errorf("message %q created result state, want none", message)
		}
	}
}

// mustParseURL parses a path-only URL for request construction in tests.
func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("failed to parse URL %q: %v", raw, err)
	}
	return parsed
}
