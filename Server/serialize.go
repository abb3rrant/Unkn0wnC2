package main

import (
	"fmt"
	"strings"
)

// appendUint16 appends a big-endian uint16 to b and returns the grown slice.
// appendUint16 appends a 16-bit unsigned integer to a byte slice in network byte order,
// used for constructing DNS packet headers and resource records.
func appendUint16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

// appendUint32 appends a big-endian uint32 to b and returns the grown slice.
// appendUint32 appends a 32-bit unsigned integer to a byte slice in network byte order,
// used for DNS TTL values and other 32-bit fields in DNS records.
func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

// appendName appends a DNS name in label form (no compression) to b.
// For example, "www.example.com" becomes: 3 www 7 example 3 com 0
// appendName encodes a domain name in DNS wire format and appends it to a byte slice,
// using length-prefixed labels as specified in RFC 1035.
func appendName(b []byte, name string) ([]byte, error) {
	if name == "" {
		return append(b, 0x00), nil
	}
	labels := strings.Split(name, ".")
	for _, lab := range labels {
		if lab == "" {
			continue
		}
		if len(lab) > 63 {
			return nil, fmt.Errorf("DNS label exceeds 63 bytes (%d): %.20s...", len(lab), lab)
		}
		b = append(b, byte(len(lab)))
		b = append(b, lab...)
	}
	b = append(b, 0x00)
	return b, nil
}

// appendNameCompressed encodes a DNS name using label compression per RFC 1035.
// nameOffsets maps domain suffixes to their offset in the message for reuse.
// appendNameCompressed encodes a domain name with DNS compression support,
// using compression pointers to reduce packet size when names are repeated.
func appendNameCompressed(b []byte, name string, nameOffsets map[string]int) ([]byte, error) {
	if name == "" || name == "." {
		return append(b, 0), nil
	}
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if off, ok := nameOffsets[suffix]; ok {
			ptr := 0xC000 | off
			b = append(b, byte(ptr>>8), byte(ptr))
			return b, nil
		}
		nameOffsets[suffix] = len(b)
		lab := labels[i]
		if lab == "" {
			continue
		}
		if len(lab) > 63 {
			return nil, fmt.Errorf("DNS label exceeds 63 bytes (%d): %.20s...", len(lab), lab)
		}
		b = append(b, byte(len(lab)))
		b = append(b, lab...)
	}
	b = append(b, 0)
	return b, nil
}

// serializeMessage converts a DNSMessage into wire bytes.
// Implements basic name compression during serialization.
// serializeMessage converts a DNSMessage struct to wire format bytes
// for transmission over UDP, following RFC 1035 packet structure.
func serializeMessage(m DNSMessage) ([]byte, error) {
	var buf []byte
	var err error
	nameOffsets := make(map[string]int)

	buf = appendUint16(buf, m.Header.ID)
	buf = appendUint16(buf, m.Header.Flags)
	buf = appendUint16(buf, m.Header.QDCount)
	buf = appendUint16(buf, m.Header.ANCount)
	buf = appendUint16(buf, m.Header.NSCount)
	buf = appendUint16(buf, m.Header.ARCount)

	for _, q := range m.Questions {
		if buf, err = appendNameCompressed(buf, q.Name, nameOffsets); err != nil {
			return nil, err
		}
		buf = appendUint16(buf, q.Type)
		buf = appendUint16(buf, q.Class)
	}

	for _, rr := range m.Answers {
		if buf, err = appendNameCompressed(buf, rr.Name, nameOffsets); err != nil {
			return nil, err
		}
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		buf = appendUint16(buf, uint16(len(rr.RData)))
		buf = append(buf, rr.RData...)
	}

	for _, rr := range m.Authorities {
		if buf, err = appendNameCompressed(buf, rr.Name, nameOffsets); err != nil {
			return nil, err
		}
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		buf = appendUint16(buf, uint16(len(rr.RData)))
		buf = append(buf, rr.RData...)
	}

	for _, rr := range m.Additionals {
		if buf, err = appendNameCompressed(buf, rr.Name, nameOffsets); err != nil {
			return nil, err
		}
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		buf = appendUint16(buf, uint16(len(rr.RData)))
		buf = append(buf, rr.RData...)
	}

	return buf, nil
}

// makeResponseFlags creates the Flags field for a response based on the query flags.
// We set QR=1 (response), copy OPCODE from query, copy RD, set AA if desired, RA=0, Z=0, and set RCODE.
// makeResponseFlags constructs DNS response flags based on query flags,
// authority status, and response code for proper DNS packet formatting.
func makeResponseFlags(queryFlags uint16, authoritative bool, rcode uint8) uint16 {
	var f uint16
	// QR (bit 15)
	f |= 0x8000
	// OPCODE (bits 14..11) copied from query
	f |= queryFlags & 0x7800
	// AA (bit 10)
	if authoritative {
		f |= 0x0400
	}
	// TC (bit 9) = 0 (not truncated)
	// RD (bit 8) copied from query
	f |= queryFlags & 0x0100
	// RA (bit 7) = 0 (no recursion available in this simple server)
	// Z (bits 6..4) = 0 (reserved)
	// RCODE (bits 3..0)
	f |= uint16(rcode) & 0x000F
	return f
}

// buildResponse takes a parsed query and a list of answers and returns a DNSMessage
// set as a response with appropriate header counts and flags.
// buildResponse constructs a DNS response message from a query and answer records,
// setting appropriate flags and copying the question section.
func buildResponse(query DNSMessage, answers []DNSResourceRecord, rcode uint8) DNSMessage {
	var m DNSMessage
	m.Header.ID = query.Header.ID
	m.Header.Flags = makeResponseFlags(query.Header.Flags, true /*AA*/, rcode)
	m.Header.QDCount = query.Header.QDCount
	m.Header.ANCount = uint16(len(answers))
	m.Questions = query.Questions
	m.Answers = answers
	addEdnsIfRequested(&m, query)
	m.Header.NSCount = uint16(len(m.Authorities))
	m.Header.ARCount = uint16(len(m.Additionals))
	return m
}

func queryHasEdns(msg DNSMessage) bool {
	for _, rr := range msg.Additionals {
		if rr.Type == 41 {
			return true
		}
	}
	return false
}

func addEdnsIfRequested(resp *DNSMessage, query DNSMessage) {
	if !queryHasEdns(query) {
		return
	}
	for _, rr := range resp.Additionals {
		if rr.Type == 41 {
			return
		}
	}
	resp.Additionals = append(resp.Additionals, DNSResourceRecord{
		Name:  ".",
		Type:  41,
		Class: 1232,
		TTL:   0,
		RData: nil,
	})
}
