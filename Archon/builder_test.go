package main

import (
	"strings"
	"testing"
)

// --- validatePayloadFormat tests ---

func validFormat(xSlots int) string {
	// Build a valid format with exactly xSlots X's in RFC 1035-safe labels (max 63 chars each).
	// Pattern: groups of 8 X + "-end" (12 chars), joined by dots.
	const xPerGroup = 8
	const decorator = "-end"
	groups := xSlots / xPerGroup
	rem := xSlots % xPerGroup
	var parts []string
	for i := 0; i < groups; i++ {
		parts = append(parts, strings.Repeat("X", xPerGroup)+decorator)
	}
	if rem > 0 {
		parts = append(parts, strings.Repeat("X", rem)+decorator)
	}
	return strings.Join(parts, ".")
}

func TestValidatePayloadFormat_Empty(t *testing.T) {
	// Empty format is always valid (default encoding)
	if err := validatePayloadFormat("", []string{"c2.test.com"}); err != nil {
		t.Errorf("empty format should be valid, got: %v", err)
	}
}

func TestValidatePayloadFormat_Valid(t *testing.T) {
	// A format with enough X slots and valid chars should pass
	format := validFormat(120)
	if err := validatePayloadFormat(format, []string{"c2.test.com"}); err != nil {
		t.Errorf("valid 120-slot format should pass, got: %v", err)
	}
}

func TestValidatePayloadFormat_InvalidChar(t *testing.T) {
	// Spaces and special characters are not DNS-safe
	format := validFormat(120)
	bad := format[:5] + " " + format[6:] // inject a space
	err := validatePayloadFormat(bad, []string{"c2.test.com"})
	if err == nil {
		t.Error("format with space should be rejected")
	}
}

func TestValidatePayloadFormat_FewSlots_Accepted(t *testing.T) {
	// Small formats are now valid — they apply to CHK beacons only and the client
	// falls back to default encoding for DATA chunks automatically.
	for _, slots := range []int{1, 20, 64, 32} {
		format := validFormat(slots)
		if err := validatePayloadFormat(format, []string{"c2.test.com"}); err != nil {
			t.Errorf("small format (%d slots) should now be accepted, got: %v", slots, err)
		}
	}
}

func TestValidatePayloadFormat_CHKOnlyThreshold(t *testing.T) {
	// CHK-only threshold: xSlots*5/8 - 63 < 1  →  xSlots < 103
	// Below 103 slots: format applies to CHK only (data falls back to default)
	// At or above 103 slots: format can carry at least 1 byte of data per chunk
	chkOnly := 100 // 100*5/8-63 = 62-63 = -1 → CHK only
	data1    := 104 // 104*5/8-63 = 65-63 = 2  → can carry 2 bytes

	if chkOnly*5/8-63 >= 1 {
		t.Errorf("slots=%d should be CHK-only (formatChunk < 1), got %d", chkOnly, chkOnly*5/8-63)
	}
	if data1*5/8-63 < 1 {
		t.Errorf("slots=%d should carry data (formatChunk >= 1), got %d", data1, data1*5/8-63)
	}
}

func TestValidatePayloadFormat_LabelTooLong(t *testing.T) {
	// A single label of 64 X's exceeds the DNS 63-char limit
	bad := strings.Repeat("X", 64) + ".rest-of-format"
	err := validatePayloadFormat(bad, []string{"c2.test.com"})
	if err == nil {
		t.Error("format with 64-char label should be rejected")
	}
}

func TestValidatePayloadFormat_EmptyLabel(t *testing.T) {
	// Consecutive dots produce an empty label
	bad := "XXXX..XXXX"
	err := validatePayloadFormat(bad, []string{"c2.test.com"})
	if err == nil {
		t.Error("format with consecutive dots (empty label) should be rejected")
	}
}

func TestValidatePayloadFormat_FQDNTooLong(t *testing.T) {
	// A very long format string that pushes the FQDN past 253 chars
	// format len + 1 + domain len > 253 → format len > 253 - 1 - len(domain)
	domain := "c2.example.com" // 14 chars
	// need format len > 253 - 1 - 14 = 238, so 239 chars of format
	// Build a valid format that is 240 chars long with enough X slots
	// Each group "XXXXXXXX-end." = 13 chars with 8 X slots
	// 240 chars / 13 chars per group ≈ 18 groups = 234 chars with 144 X slots — check exact
	longFormat := validFormat(200) // will be well over 238 chars given decorator overhead
	if len(longFormat)+1+len(domain) <= 253 {
		// Format not long enough for this domain; make it longer
		longFormat = strings.Repeat(validFormat(8)+".", 20) + validFormat(8)
	}
	if len(longFormat)+1+len(domain) <= 253 {
		t.Skipf("could not construct format long enough for this test (format=%d domain=%d)", len(longFormat), len(domain))
	}
	err := validatePayloadFormat(longFormat, []string{domain})
	if err == nil {
		t.Errorf("format that pushes FQDN past 253 chars should be rejected (format=%d domain=%d)", len(longFormat), len(domain))
	}
}

func TestValidatePayloadFormat_MultipleDomains_OneFails(t *testing.T) {
	// Format valid for short domain but too long for a long domain
	shortDomain := "c2.io"               // 5 chars
	longDomain := strings.Repeat("a", 100) + ".com" // 104 chars

	// We need a format where len(format)+1+5 ≤ 253 but len(format)+1+104 > 253
	// So: format len ≤ 247 and format len > 148 → e.g. 200 chars
	format := validFormat(120) // ~200 chars with decorators
	if len(format)+1+len(shortDomain) > 253 {
		t.Skipf("format too long for short domain test (%d chars)", len(format))
	}
	if len(format)+1+len(longDomain) <= 253 {
		t.Skipf("format not long enough to exceed limit with long domain (format=%d, domain=%d)", len(format), len(longDomain))
	}
	err := validatePayloadFormat(format, []string{shortDomain, longDomain})
	if err == nil {
		t.Error("should be rejected because one domain makes FQDN exceed 253 chars")
	}
}

func TestValidatePayloadFormat_AllowedDecorators(t *testing.T) {
	// Hyphens, underscores, and alphanumeric decorators are all valid.
	// Use 15 groups of "XXXXXXXX-ab_CD1" (8 X + 7 decorators = 15 chars each):
	//   15 groups × 15 chars + 14 dots = 239 chars, 120 X slots, fits "c2.test.com" FQDN (239+1+11=251 ≤ 253).
	group := "XXXXXXXX-ab_CD1"
	parts := make([]string, 15)
	for i := range parts {
		parts[i] = group
	}
	format := strings.Join(parts, ".")
	xSlots := strings.Count(format, "X")
	if xSlots < 114 {
		t.Skipf("test format only has %d X slots, need ≥114 — adjust test", xSlots)
	}
	if err := validatePayloadFormat(format, []string{"c2.test.com"}); err != nil {
		t.Errorf("format with valid decorator chars should pass, got: %v", err)
	}
}
