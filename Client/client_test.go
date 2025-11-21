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

func TestDNSClientInit(t *testing.T) {
	client := newDNSClient()
	if client == nil {
		t.Fatal("Failed to create DNSClient")
	}

	if client.config == nil {
		t.Error("Config should not be nil")
	}
}
