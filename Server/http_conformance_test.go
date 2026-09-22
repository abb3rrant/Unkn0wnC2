package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

// conformanceVectors mirrors testdata/http_transport_vectors.json.
type conformanceVectors struct {
	Passphrase string `json:"passphrase"`
	Signature  struct {
		Method    string `json:"method"`
		Path      string `json:"path"`
		Timestamp string `json:"timestamp"`
		Body      string `json:"body"`
		ExpectHex string `json:"expect_hex"`
	} `json:"signature"`
	Base36 struct {
		Plaintext string `json:"plaintext"`
		Encoded   string `json:"encoded"`
	} `json:"base36"`
	Base64 struct {
		Plaintext string `json:"plaintext"`
		Encoded   string `json:"encoded"`
	} `json:"base64"`
	AESGCMBase36 struct {
		Plaintext string `json:"plaintext"`
		Encoded   string `json:"encoded"`
	} `json:"aes_gcm_base36"`
	AESGCMBase64 struct {
		Plaintext string `json:"plaintext"`
		Encoded   string `json:"encoded"`
	} `json:"aes_gcm_base64"`
}

// loadConformanceVectors reads the shared vectors.
func loadConformanceVectors(t *testing.T) conformanceVectors {
	t.Helper()

	raw, err := os.ReadFile("../testdata/http_transport_vectors.json")
	if err != nil {
		t.Fatalf("failed to read the shared conformance vectors: %v", err)
	}

	var vectors conformanceVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("failed to parse the shared conformance vectors: %v", err)
	}
	return vectors
}

// TestHTTPTransportConformance pins this module's HTTP transport to the shared
// vectors, which the Client module asserts with its own copy of the codec.
//
// The codec and the signature scheme exist twice, because the DNS server and the
// beacon are separate Go modules. A change on one side that the other does not
// make would otherwise show up as beacons that register but never receive a task,
// or results that arrive as undecryptable garbage. The vectors are what turns that
// into a test failure instead.
func TestHTTPTransportConformance(t *testing.T) {
	vectors := loadConformanceVectors(t)
	key := generateAESKey(vectors.Passphrase)

	t.Run("signature", func(t *testing.T) {
		mac := hmac.New(sha256.New, hmacKey(key))
		mac.Write([]byte(vectors.Signature.Method + "\n" + vectors.Signature.Path + "\n" +
			vectors.Signature.Timestamp + "\n" + vectors.Signature.Body))

		actual := hex.EncodeToString(mac.Sum(nil))
		if actual != vectors.Signature.ExpectHex {
			t.Fatalf("signature drifted from the shared vector:\n  computed %s\n  vector   %s", actual, vectors.Signature.ExpectHex)
		}
	})

	t.Run("base36", func(t *testing.T) {
		if encoded := base36EncodeString(vectors.Base36.Plaintext); encoded != vectors.Base36.Encoded {
			t.Errorf("base36 encode = %q, want %q", encoded, vectors.Base36.Encoded)
		}
		decoded, err := base36DecodeString(vectors.Base36.Encoded)
		if err != nil {
			t.Fatalf("base36 decode error = %v", err)
		}
		if decoded != vectors.Base36.Plaintext {
			t.Errorf("base36 decode = %q, want %q", decoded, vectors.Base36.Plaintext)
		}
	})

	t.Run("base64", func(t *testing.T) {
		if encoded := base64.StdEncoding.EncodeToString([]byte(vectors.Base64.Plaintext)); encoded != vectors.Base64.Encoded {
			t.Errorf("base64 encode = %q, want %q", encoded, vectors.Base64.Encoded)
		}
		decoded, err := base64.StdEncoding.DecodeString(vectors.Base64.Encoded)
		if err != nil {
			t.Fatalf("base64 decode error = %v", err)
		}
		if string(decoded) != vectors.Base64.Plaintext {
			t.Errorf("base64 decode = %q, want %q", decoded, vectors.Base64.Plaintext)
		}
	})

	t.Run("aes-gcm-base36", func(t *testing.T) {
		decoded, err := decodeAndDecrypt(vectors.AESGCMBase36.Encoded, key)
		if err != nil {
			t.Fatalf("aes-gcm-base36 decode error = %v", err)
		}
		if decoded != vectors.AESGCMBase36.Plaintext {
			t.Errorf("aes-gcm-base36 decode = %q, want %q", decoded, vectors.AESGCMBase36.Plaintext)
		}
	})

	t.Run("aes-gcm-base64", func(t *testing.T) {
		ciphertext, err := base64.StdEncoding.DecodeString(vectors.AESGCMBase64.Encoded)
		if err != nil {
			t.Fatalf("vector is not valid base64: %v", err)
		}
		plaintext, err := decryptAESGCM(ciphertext, key)
		if err != nil {
			t.Fatalf("aes-gcm-base64 decrypt error = %v", err)
		}
		if string(plaintext) != vectors.AESGCMBase64.Plaintext {
			t.Errorf("aes-gcm-base64 decode = %q, want %q", plaintext, vectors.AESGCMBase64.Plaintext)
		}
	})
}
