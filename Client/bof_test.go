package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func sampleBOF(t *testing.T) []byte {
	t.Helper()
	object, err := os.ReadFile("testdata/sample.bof")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return object
}

func bofDocument(t *testing.T, args string) string {
	t.Helper()
	payload := base64.StdEncoding.EncodeToString(sampleBOF(t))
	document, err := json.Marshal(bofTask{Name: "sample.bof", Args: args, Data: payload})
	if err != nil {
		t.Fatalf("marshal task: %v", err)
	}
	return string(document)
}

// A real object file, built by mingw, must parse and pass the COFF check.
func TestParseBOFTask_AcceptsRealCOFFObject(t *testing.T) {
	request, err := parseBOFTask(bofDocument(t, "one two"))
	if err != nil {
		t.Fatalf("parseBOFTask() error = %v", err)
	}
	if request.Name != "sample.bof" {
		t.Errorf("name = %q, want sample.bof", request.Name)
	}
	if len(request.Object) != len(sampleBOF(t)) {
		t.Errorf("object length = %d, want %d", len(request.Object), len(sampleBOF(t)))
	}
	if got := string(request.ArgsCB); got != "one two\x00" {
		t.Errorf("args buffer = %q, want a NUL-terminated copy", got)
	}
	// This is what the loader keys off, so assert it against the real object.
	if machine := binary.LittleEndian.Uint16(request.Object[0:2]); machine != coffMachineAMD64 {
		t.Errorf("fixture machine = 0x%04x, want 0x%04x", machine, coffMachineAMD64)
	}
}

func TestParseBOFTask_RejectsBadDocuments(t *testing.T) {
	oversized := base64.StdEncoding.EncodeToString(make([]byte, maxBOFPayloadBytes+1))
	arm64 := make([]byte, 64)
	binary.LittleEndian.PutUint16(arm64[0:2], coffMachineARM64)
	wrongMachine := make([]byte, 64)
	binary.LittleEndian.PutUint16(wrongMachine[0:2], 0x014c) // i386

	cases := map[string]struct {
		payload string
		want    string
	}{
		"not json":       {`{"name":`, "malformed task document"},
		"no data":        {`{"name":"x.bof"}`, "carries no object file"},
		"bad base64":     {`{"data":"!!!not-base64!!!"}`, "not valid base64"},
		"over the limit": {`{"data":"` + oversized + `"}`, "over the"},
		"too short":      {`{"data":"` + base64.StdEncoding.EncodeToString([]byte{0x64, 0x86}) + `"}`, "too short"},
		"arm64 object":   {`{"data":"` + base64.StdEncoding.EncodeToString(arm64) + `"}`, "arm64"},
		"wrong machine":  {`{"data":"` + base64.StdEncoding.EncodeToString(wrongMachine) + `"}`, "not a COFF x86-64 object"},
	}

	for name, testCase := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseBOFTask(testCase.payload)
			if err == nil {
				t.Fatalf("parseBOFTask() accepted %s", name)
			}
			if !strings.Contains(err.Error(), testCase.want) {
				t.Errorf("error = %q, want it to mention %q", err, testCase.want)
			}
		})
	}
}

// The transport guard is the operator-facing rule: a DNS-only beacon refuses the
// task instead of trying to pull half a megabyte through DNS labels.
func TestHandleBOFCommand_RefusesWhenNotOnHTTP(t *testing.T) {
	cases := map[string]*transportManager{
		"no transport (dns build)": nil,
		"explicitly dns":           {mode: transportDNS},
	}

	for name, manager := range cases {
		t.Run(name, func(t *testing.T) {
			beacon := &Beacon{transport: manager}
			result := beacon.handleBOFCommand(bofDocument(t, ""))

			if !strings.Contains(result, "BOF refused") {
				t.Fatalf("result = %q, want a refusal", result)
			}
			if !strings.Contains(result, "http") && !strings.Contains(result, "HTTP") {
				t.Errorf("result = %q, should name the transport requirement", result)
			}
		})
	}
}

func TestHandleBOFCommand_AcceptsHTTPAndDual(t *testing.T) {
	for _, mode := range []string{transportHTTP, transportDual} {
		t.Run(mode, func(t *testing.T) {
			beacon := &Beacon{transport: &transportManager{mode: mode}}
			result := beacon.handleBOFCommand(bofDocument(t, ""))

			if strings.Contains(result, "BOF refused") {
				t.Fatalf("%s beacon refused the task: %q", mode, result)
			}
			// On a platform without the loader the task is rejected with a
			// platform message; on windows/amd64 it would run the object.
			if strings.Contains(result, "BOF rejected") {
				t.Fatalf("%s beacon rejected a valid document: %q", mode, result)
			}
		})
	}
}

// A malformed document must be reported, not executed, on an HTTP beacon.
func TestHandleBOFCommand_RejectsMalformedDocument(t *testing.T) {
	beacon := &Beacon{transport: &transportManager{mode: transportHTTP}}

	result := beacon.handleBOFCommand(`{"data":"bm9wZQ=="}`) // "nope", not a COFF file
	if !strings.Contains(result, "BOF rejected") {
		t.Fatalf("result = %q, want a rejection", result)
	}
	if !strings.Contains(result, "too short") && !strings.Contains(result, "COFF") {
		t.Errorf("result = %q, should explain why the object was refused", result)
	}
}
