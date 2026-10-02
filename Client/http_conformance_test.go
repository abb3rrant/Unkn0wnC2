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

// TestHTTPTransportConformance pins this module's HTTP transport to the shared
// vectors, which the Server module asserts with its own copy of the codec.
//
// The codec and the signature scheme exist twice, because the beacon and the DNS
// server are separate Go modules. A change on one side that the other does not make
// would otherwise show up as a beacon that registers but never receives a task, or
// results that arrive as undecryptable garbage. The vectors are what turns that into
// a test failure instead.
func TestHTTPTransportConformance(t *testing.T) {
	raw, err := os.ReadFile("../testdata/http_transport_vectors.json")
	if err != nil {
		t.Fatalf("failed to read the shared conformance vectors: %v", err)
	}

	var vectors struct {
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
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatalf("failed to parse the shared conformance vectors: %v", err)
	}

	key := generateAESKey(vectors.Passphrase)

	// The beacon derives its signing key through the transport, so the test uses
	// that path rather than reimplementing the derivation.
	transport := &httpTransport{aesKey: key}

	t.Run("signature", func(t *testing.T) {
		mac := hmac.New(sha256.New, transport.hmacKey())
		mac.Write([]byte(vectors.Signature.Method + "\n" + vectors.Signature.Path + "\n" +
			vectors.Signature.Timestamp + "\n" + vectors.Signature.Body))

		actual := hex.EncodeToString(mac.Sum(nil))
		if actual != vectors.Signature.ExpectHex {
			t.Fatalf("beacon signature does not match what the listener verifies:\n  computed %s\n  vector   %s", actual, vectors.Signature.ExpectHex)
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

	// The beacon must be able to *produce* what the listener decodes, not only read
	// the vector. Round-tripping through this module's codec and back through the
	// vector's key closes the encode direction too.
	t.Run("encode round trip", func(t *testing.T) {
		body, err := encodeHTTPBody(HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"},
			vectors.AESGCMBase36.Plaintext, key)
		if err != nil {
			t.Fatalf("encodeHTTPBody() error = %v", err)
		}
		decoded, err := decodeHTTPBody(HTTPBodyCodec{Encoding: codecAESGCMBase36, Field: "d"}, body, key)
		if err != nil {
			t.Fatalf("decodeHTTPBody() error = %v", err)
		}
		if decoded != vectors.AESGCMBase36.Plaintext {
			t.Errorf("round trip = %q, want %q", decoded, vectors.AESGCMBase36.Plaintext)
		}
	})
}
