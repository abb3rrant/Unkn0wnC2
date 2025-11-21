package main

import (
	"testing"
)

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

func TestC2ManagerInit(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")
	if c2 == nil {
		t.Fatal("Failed to create C2Manager")
	}

	if string(c2.domain) != "example.com" {
		t.Errorf("Domain mismatch. Got %s, want example.com", c2.domain)
	}
}

func TestBeaconRegistration(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")

	// Simulate beacon checkin
	beaconData := `{"id":"test-beacon","hostname":"host1","username":"user1","os":"linux","arch":"amd64"}`

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

func TestTasking(t *testing.T) {
	c2 := NewC2Manager(true, "testkey", StagerJitter{JitterMinMs: 100, JitterMaxMs: 200}, ":memory:", "example.com")

	// Register beacon first
	beaconData := `{"id":"test-beacon","hostname":"host1","username":"user1","os":"linux","arch":"amd64"}`
	encoded, _ := encryptAndEncode(beaconData, c2.aesKey)
	c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Add task
	c2.AddTaskFromMaster("M1", "test-beacon", "whoami")

	// Poll for task
	resp, _ := c2.processBeaconQuery(encoded+".example.com", "127.0.0.1")

	// Response should be TASK|ID|COMMAND
	if len(resp) < 5 || resp[:5] != "TASK|" {
		t.Errorf("Expected TASK response, got %s", resp)
	}
}
