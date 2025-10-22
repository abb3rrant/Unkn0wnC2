// Package main implements cryptographic functions for the Unkn0wnC2 DNS C2 framework.
// This provides AES-GCM encryption/decryption and Base36 encoding for secure
// DNS-compatible C2 communications.
package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"strings"
)

// generateAESKey generates a 32-byte AES key from a passphrase
// generateAESKey derives a 256-bit AES key from a passphrase using SHA256 hashing
// for consistent key generation across server and client components.
func generateAESKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// encryptAESGCM encrypts data using AES-GCM
// encryptAESGCM encrypts data using AES-GCM with a random nonce,
// providing both confidentiality and authenticity for C2 communications.
func encryptAESGCM(data []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	// Generate random nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %v", err)
	}

	// Encrypt and authenticate
	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

// decryptAESGCM decrypts data using AES-GCM
// decryptAESGCM decrypts AES-GCM encrypted data, extracting the nonce
// and verifying authenticity before returning the plaintext.
func decryptAESGCM(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %v", err)
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM: %v", err)
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt: %v", err)
	}

	return plaintext, nil
}

// base36Encode encodes data to base36 string
// base36Encode converts binary data to Base36 encoding for DNS-compatible transmission,
// using characters 0-9 and a-z to represent data in DNS subdomains.
func base36Encode(data []byte) string {
	// Convert bytes to big integer
	num := new(big.Int)
	num.SetBytes(data)

	// Convert to base36
	return strings.ToLower(num.Text(36))
}

// base36Decode decodes base36 string to bytes
// base36Decode converts a Base36 encoded string back to binary data,
// reversing the DNS-compatible encoding used for C2 communications.
func base36Decode(encoded string) ([]byte, error) {
	// Parse base36 string to big integer
	num := new(big.Int)
	num, ok := num.SetString(encoded, 36)
	if !ok {
		return nil, fmt.Errorf("invalid base36 string")
	}

	// Convert to bytes
	return num.Bytes(), nil
}

// encryptAndEncode encrypts data with AES-GCM and encodes with base36
// encryptAndEncode combines AES-GCM encryption with Base36 encoding
// to prepare data for transmission through DNS queries.
func encryptAndEncode(data string, key []byte) (string, error) {
	// Encrypt with AES-GCM
	encrypted, err := encryptAESGCM([]byte(data), key)
	if err != nil {
		return "", fmt.Errorf("encryption failed: %v", err)
	}

	// Encode with base36
	encoded := base36Encode(encrypted)
	return encoded, nil
}

// decodeAndDecrypt decodes base36 and decrypts with AES-GCM
// decodeAndDecrypt combines Base36 decoding with AES-GCM decryption
// to extract plaintext data from DNS-transmitted C2 communications.
func decodeAndDecrypt(encoded string, key []byte) (string, error) {
	// DNS is case-insensitive, so normalize to lowercase
	encoded = strings.ToLower(encoded)

	// Decode from base36
	encrypted, err := base36Decode(encoded)
	if err != nil {
		return "", fmt.Errorf("base36 decode failed: %v", err)
	}

	// Decrypt with AES-GCM
	decrypted, err := decryptAESGCM(encrypted, key)
	if err != nil {
		return "", fmt.Errorf("decryption failed: %v", err)
	}

	return string(decrypted), nil
}

// base36EncodeString encodes a plain string to base36 (no encryption)
// Used for stager communications where encryption is not needed
func base36EncodeString(data string) string {
	return base36Encode([]byte(data))
}

// base36DecodeString decodes a base36 string to plain text (no decryption)
// Used for stager communications where encryption is not needed
func base36DecodeString(encoded string) (string, error) {
	// DNS is case-insensitive, so normalize to lowercase
	encoded = strings.ToLower(encoded)
	decoded, err := base36Decode(encoded)
	if err != nil {
		return "", err
	}
	return string(decoded), nil
}

// Legacy functions for backward compatibility during transition
// These will be removed once we fully migrate
