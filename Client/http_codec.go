// Package main implements the body codecs for the malleable HTTP transport.
//
// This mirrors Server/http_codec.go. The two live in separate modules (the
// client is cross-compiled standalone by Archon), which is the same reason
// crypto.go is duplicated between them. The codecs must stay byte-compatible:
// TestHTTPCodecMatchesServerWireFormat in the Server module pins the format.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// Body codecs, matching the server's profile field values.
const (
	codecRaw          = "raw"
	codecBase64       = "base64"
	codecBase36       = "base36"
	codecAESGCMBase64 = "aes-gcm-base64"
	codecAESGCMBase36 = "aes-gcm-base36"
)

// encodeHTTPBody renders a protocol string as an HTTP body per the codec.
func encodeHTTPBody(c HTTPBodyCodec, plaintext string, key []byte) ([]byte, error) {
	if c.Encoding == codecRaw || c.Encoding == "" {
		return []byte(plaintext), nil
	}

	fields := make(map[string]string, 2)

	switch c.Encoding {
	case codecBase64:
		fields[c.Field] = base64.StdEncoding.EncodeToString([]byte(plaintext))

	case codecBase36:
		fields[c.Field] = base36EncodeString(plaintext)

	case codecAESGCMBase64:
		ciphertext, err := encryptAESGCM([]byte(plaintext), key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt body: %w", err)
		}
		fields[c.Field] = base64.StdEncoding.EncodeToString(ciphertext)

	case codecAESGCMBase36:
		ciphertext, err := encryptAESGCM([]byte(plaintext), key)
		if err != nil {
			return nil, fmt.Errorf("failed to encrypt body: %w", err)
		}
		fields[c.Field] = base36Encode(ciphertext)

	default:
		return nil, fmt.Errorf("unsupported body encoding %q", c.Encoding)
	}

	// Random padding keeps body length off a fixed grid, so a listener's
	// response-size distribution is not a stable signature.
	if c.PaddingFld != "" && c.PadMax > 0 {
		padding, err := randomPadding(c.PadMin, c.PadMax)
		if err != nil {
			return nil, err
		}
		fields[c.PaddingFld] = padding
	}

	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal body: %w", err)
	}
	return encoded, nil
}

// decodeHTTPBody reverses encodeHTTPBody.
func decodeHTTPBody(c HTTPBodyCodec, body []byte, key []byte) (string, error) {
	if c.Encoding == codecRaw || c.Encoding == "" {
		return string(body), nil
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(body, &envelope); err != nil {
		return "", fmt.Errorf("body is not a JSON object: %w", err)
	}

	raw, ok := envelope[c.Field]
	if !ok {
		return "", fmt.Errorf("body is missing field %q", c.Field)
	}

	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("field %q is not a string: %w", c.Field, err)
	}

	switch c.Encoding {
	case codecBase64:
		decoded, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("failed to base64-decode body: %w", err)
		}
		return string(decoded), nil

	case codecBase36:
		decoded, err := base36DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("failed to base36-decode body: %w", err)
		}
		return string(decoded), nil

	case codecAESGCMBase64:
		ciphertext, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return "", fmt.Errorf("failed to base64-decode body: %w", err)
		}
		plaintext, err := decryptAESGCM(ciphertext, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt body: %w", err)
		}
		return string(plaintext), nil

	case codecAESGCMBase36:
		ciphertext, err := base36Decode(value)
		if err != nil {
			return "", fmt.Errorf("failed to base36-decode body: %w", err)
		}
		plaintext, err := decryptAESGCM(ciphertext, key)
		if err != nil {
			return "", fmt.Errorf("failed to decrypt body: %w", err)
		}
		return string(plaintext), nil
	}

	return "", fmt.Errorf("unsupported body encoding %q", c.Encoding)
}

// randomPadding returns a random alphanumeric string in [min, max] length.
func randomPadding(minLength, maxLength int) (string, error) {
	if maxLength < minLength {
		minLength, maxLength = maxLength, minLength
	}
	if maxLength <= 0 {
		return "", nil
	}

	span := maxLength - minLength + 1
	offset, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return "", fmt.Errorf("failed to pick padding length: %w", err)
	}
	length := minLength + int(offset.Int64())
	if length == 0 {
		return "", nil
	}

	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	out := make([]byte, length)
	for i := range out {
		index, err := rand.Int(rand.Reader, big.NewInt(int64(len(alphabet))))
		if err != nil {
			return "", fmt.Errorf("failed to generate padding: %w", err)
		}
		out[i] = alphabet[index.Int64()]
	}
	return string(out), nil
}
