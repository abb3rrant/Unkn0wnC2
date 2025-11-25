// Package main implements cryptographic functions for the Unkn0wnC2 DNS C2 client.
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

	"golang.org/x/crypto/pbkdf2"
)

// generateAESKey derives a 256-bit AES key from a passphrase using PBKDF2
// with SHA256, 100,000 iterations, and a fixed salt derived from the passphrase.
// This provides better protection against brute force attacks compared to simple hashing.
// The salt is deterministic (based on passphrase) to ensure consistent keys across
// server and client components.
func generateAESKey(passphrase string) []byte {
	// Use first 32 chars of passphrase as salt (padded/truncated if needed)
	// This ensures the same passphrase always produces the same key
	salt := []byte(passphrase)
	if len(salt) < 32 {
		// Pad with the passphrase repeated
		for len(salt) < 32 {
			salt = append(salt, []byte(passphrase)...)
		}
	}
	salt = salt[:32]

	// PBKDF2 with 100,000 iterations (OWASP recommendation for 2023+)
	key := pbkdf2.Key([]byte(passphrase), salt, 100000, 32, sha256.New)
	return key
}

// encryptAESGCM encrypts data using AES-GCM
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
func base36Encode(data []byte) string {
	// Convert bytes to big integer
	num := new(big.Int)
	num.SetBytes(data)

	// Convert to base36
	return strings.ToLower(num.Text(36))
}

// base36Decode decodes base36 string to bytes
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
