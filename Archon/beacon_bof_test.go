package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/mux"
)

// sampleBOFObject loads the real COFF fixture the client tests also use, so the
// API validates exactly the kind of object the loader will receive.
func sampleBOFObject(t *testing.T) []byte {
	t.Helper()
	object, err := os.ReadFile("../Client/testdata/sample.bof")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return object
}

// bofRequestFor builds a request against the mux route so mux.Vars carries the id.
func bofRequestFor(t *testing.T, beaconID, body string) *http.Request {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "/api/beacons/"+beaconID+"/bof", strings.NewReader(body))
	return mux.SetURLVars(request, map[string]string{"id": beaconID})
}

func bofBody(t *testing.T, object []byte) string {
	t.Helper()
	encoded, err := json.Marshal(map[string]string{
		"name": "sample.bof",
		"args": "one two",
		"data": base64.StdEncoding.EncodeToString(object),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(encoded)
}

func TestRunBOF_QueuesTaskForKnownObject(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-bof"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	recorder := httptest.NewRecorder()
	api.handleRunBOF(recorder, bofRequestFor(t, "beacon-bof", bofBody(t, sampleBOFObject(t))))

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	var response struct {
		Success bool `json:"success"`
		Data    struct {
			TaskID string `json:"task_id"`
			Name   string `json:"name"`
			Bytes  int    `json:"bytes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("response is not JSON: %v", err)
	}
	if !response.Success || response.Data.TaskID == "" {
		t.Fatalf("no task queued: %s", recorder.Body.String())
	}
	if response.Data.Bytes != len(sampleBOFObject(t)) {
		t.Errorf("bytes = %d, want %d", response.Data.Bytes, len(sampleBOFObject(t)))
	}

	// The task has to carry the marker the beacon dispatches on, plus the object.
	tasks, err := db.GetTasksForDNSServer("dns-server-A")
	if err != nil {
		t.Fatalf("read tasks: %v", err)
	}
	var found string
	for _, task := range tasks {
		if task.ID == response.Data.TaskID {
			found = task.Command
		}
	}
	if found == "" {
		t.Fatalf("task %s not visible to the listener", response.Data.TaskID)
	}
	if !strings.HasPrefix(found, bofCommandPrefix) {
		t.Fatalf("task command = %q, want the %q prefix", truncate(found, 40), bofCommandPrefix)
	}

	var document map[string]string
	if err := json.Unmarshal([]byte(strings.TrimPrefix(found, bofCommandPrefix)), &document); err != nil {
		t.Fatalf("task payload is not JSON: %v", err)
	}
	if decoded, err := base64.StdEncoding.DecodeString(document["data"]); err != nil || len(decoded) != len(sampleBOFObject(t)) {
		t.Fatalf("task payload does not carry the object back (%d bytes, err %v)", len(decoded), err)
	}
}

func TestRunBOF_RejectsBadRequests(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-bof"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	i386 := make([]byte, 64)
	binary.LittleEndian.PutUint16(i386[0:2], 0x014c)
	oversized := make([]byte, maxBOFObjectBytes+1)
	binary.LittleEndian.PutUint16(oversized[0:2], coffMachineAMD64)

	cases := map[string]struct {
		beacon string
		body   string
		want   int
	}{
		"unknown beacon": {beacon: "nope", body: bofBody(t, sampleBOFObject(t)), want: http.StatusNotFound},
		"bad base64":     {beacon: "beacon-bof", body: `{"data":"***"}`, want: http.StatusBadRequest},
		"no object":      {beacon: "beacon-bof", body: `{"data":""}`, want: http.StatusBadRequest},
		"too short":      {beacon: "beacon-bof", body: `{"data":"` + base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) + `"}`, want: http.StatusBadRequest},
		"wrong machine":  {beacon: "beacon-bof", body: bofBody(t, i386), want: http.StatusBadRequest},
		"over the limit": {beacon: "beacon-bof", body: bofBody(t, oversized), want: http.StatusRequestEntityTooLarge},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			api.handleRunBOF(recorder, bofRequestFor(t, testCase.beacon, testCase.body))
			if recorder.Code != testCase.want {
				t.Errorf("status = %d, want %d (body %s)", recorder.Code, testCase.want, recorder.Body.String())
			}
		})
	}
}

// A beacon known to be DNS-only must be refused before anything is queued: the
// object would otherwise be pulled through subdomain labels.
func TestRunBOF_RefusesDNSStringTransport(t *testing.T) {
	if got := normalizeTransportMode("dns"); got != "dns" {
		t.Errorf("normalizeTransportMode(dns) = %q", got)
	}
	if got := normalizeTransportMode(""); got != "dns" {
		t.Errorf("normalizeTransportMode(empty) = %q, want dns", got)
	}
	if got := normalizeTransportMode(" DUAL "); got != "dual" {
		t.Errorf("normalizeTransportMode(DUAL) = %q", got)
	}
	if got := normalizeTransportMode("http"); got != "http" {
		t.Errorf("normalizeTransportMode(http) = %q", got)
	}
}

// A beacon recorded as DNS-only must be refused before anything is queued: the
// object would otherwise be pulled through subdomain labels.
func TestRunBOF_RefusesBeaconRecordedAsDNS(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-dns"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	// The dashboard records "dns" when an operator stops using HTTP listeners.
	if err := db.SetBeaconHTTPListeners("beacon-dns", nil, "dns"); err != nil {
		t.Fatalf("record transport: %v", err)
	}
	api := NewAPIServer(db, Config{})

	recorder := httptest.NewRecorder()
	api.handleRunBOF(recorder, bofRequestFor(t, "beacon-dns", bofBody(t, sampleBOFObject(t))))

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "DNS only") {
		t.Errorf("message should explain the transport requirement: %s", recorder.Body.String())
	}

	// Nothing may have been queued.
	tasks, err := db.GetTasksForDNSServer("dns-server-A")
	if err != nil {
		t.Fatalf("read tasks: %v", err)
	}
	for _, task := range tasks {
		if strings.HasPrefix(task.Command, bofCommandPrefix) {
			t.Fatalf("a BOF task was queued for a DNS-only beacon: %s", truncate(task.Command, 40))
		}
	}
}

func TestHTTPListenerSpecFromDocument_MapsBeaconFields(t *testing.T) {
	spec, err := httpListenerSpecFromDocument(defaultHTTPProfileDocument())
	if err != nil {
		t.Fatalf("httpListenerSpecFromDocument() error = %v", err)
	}

	if spec.Scheme != "http" {
		t.Errorf("scheme = %q, want http", spec.Scheme)
	}
	if spec.Host == "" {
		t.Error("host is empty: the spec would not name where the beacon dials")
	}
	for _, operation := range []string{"register", "task", "result", "ack"} {
		if len(spec.URIs[operation]) == 0 {
			t.Errorf("uris.%s is empty", operation)
		}
	}
	// Listener-only fields must not leak into the beacon copy.
	if spec.Name == "" {
		t.Error("name should be carried for logs")
	}
	if err := validateTransportListener(spec); err != nil {
		t.Errorf("projected spec does not pass the push validator: %v", err)
	}
}

func TestSetBeaconHTTPListeners_QueuesTransportUpdate(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-http"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	// The default profile is what an operator would assign.
	if _, err := db.EnsureDefaultHTTPProfile(); err != nil {
		t.Fatalf("seed profile: %v", err)
	}
	api := NewAPIServer(db, Config{})

	body := `{"names":["default"],"mode":"http"}`
	request := httptest.NewRequest(http.MethodPost, "/api/beacons/beacon-http/http-listeners", strings.NewReader(body))
	request = mux.SetURLVars(request, map[string]string{"id": "beacon-http"})

	recorder := httptest.NewRecorder()
	api.handleSetBeaconHTTPListeners(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body.String())
	}

	tasks, err := db.GetTasksForDNSServer("dns-server-A")
	if err != nil {
		t.Fatalf("read tasks: %v", err)
	}
	var command string
	for _, task := range tasks {
		if strings.HasPrefix(task.Command, "update_transport:") {
			command = task.Command
		}
	}
	if command == "" {
		t.Fatal("no update_transport task was queued")
	}
	// This beacon has no build record, so it predates the bootstrap hand-off and
	// must receive the payload it already understands. Sending it the short form
	// would make it execute the task string as a shell command.
	if !strings.Contains(command, `"mode":"http"`) {
		t.Errorf("task does not carry the requested mode: %s", truncate(command, 80))
	}
	if !strings.Contains(command, `"host":"127.0.0.1:8445"`) {
		t.Errorf("task does not carry the profile's beacon host: %s", truncate(command, 120))
	}
}

// TestBeaconSupportsHTTPBootstrap covers the capability gate: only a build that
// advertises the flag may be sent the short form.
func TestBeaconSupportsHTTPBootstrap(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-old"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	if api.beaconSupportsHTTPBootstrap("beacon-old") {
		t.Fatal("a beacon with no build record claims bootstrap support")
	}

	// Record a build that advertises the capability and point the beacon at it.
	now := time.Now().Unix()
	if _, err := db.db.Exec(`
		INSERT INTO client_binaries (id, filename, os, arch, original_size, compressed_size, base64_size, total_chunks, base64_data, dns_domains, created_at, build_id, build_config)
		VALUES ('bin-1', 'beacon', 'linux', 'amd64', 1, 1, 1, 1, '', '', ?, 'build-new', '{"http_bootstrap":true}')
	`, now); err != nil {
		t.Fatalf("seed build: %v", err)
	}
	if _, err := db.db.Exec(`UPDATE beacons SET build_id = ? WHERE id = ?`, "build-new", "beacon-old"); err != nil {
		t.Fatalf("set build id: %v", err)
	}

	if !api.beaconSupportsHTTPBootstrap("beacon-old") {
		t.Fatal("a build advertising http_bootstrap was not recognised")
	}
}

func TestSetBeaconHTTPListeners_RejectsDNSModeWithListeners(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-http"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	request := httptest.NewRequest(http.MethodPost, "/api/beacons/beacon-http/http-listeners",
		strings.NewReader(`{"names":["default"],"mode":"dns"}`))
	request = mux.SetURLVars(request, map[string]string{"id": "beacon-http"})

	recorder := httptest.NewRecorder()
	api.handleSetBeaconHTTPListeners(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 (body %s)", recorder.Code, recorder.Body.String())
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

// TestSetBeaconHTTPListeners_RefusesDNSModeWithoutDomains covers the stranding
// case: a beacon with no active DNS domain that is told to stop using HTTP has no
// transport left, and only the operator would notice — later, as silence.
func TestSetBeaconHTTPListeners_RefusesDNSModeWithoutDomains(t *testing.T) {
	db := newTestProfileDB(t)
	if err := createTestBeacon(db, "beacon-no-domains"); err != nil {
		t.Fatalf("seed beacon: %v", err)
	}
	api := NewAPIServer(db, Config{})

	request := httptest.NewRequest(http.MethodPost, "/api/beacons/beacon-no-domains/http-listeners",
		strings.NewReader(`{"names":[],"mode":"dns"}`))
	request = mux.SetURLVars(request, map[string]string{"id": "beacon-no-domains"})

	recorder := httptest.NewRecorder()
	api.handleSetBeaconHTTPListeners(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (body %s)", recorder.Code, recorder.Body.String())
	}
	if !strings.Contains(recorder.Body.String(), "unreachable") {
		t.Errorf("body does not explain the risk: %s", recorder.Body.String())
	}

	// Nothing may be queued when the change is refused.
	tasks, err := db.GetTasksForDNSServer("dns-server-A")
	if err != nil {
		t.Fatalf("read tasks: %v", err)
	}
	for _, task := range tasks {
		if strings.Contains(task.Command, "update_transport") || strings.Contains(task.Command, "http_profile:") {
			t.Fatalf("refused change queued a task: %s", truncate(task.Command, 80))
		}
	}
}
