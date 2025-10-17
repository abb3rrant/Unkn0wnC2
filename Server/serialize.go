package main

import "strings"

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
func appendName(b []byte, name string) []byte {
	if name == "" {
		// Root label
		return append(b, 0x00)
	}
	labels := strings.Split(name, ".")
	for _, lab := range labels {
		if lab == "" {
			// Ignore empty segments that might arise from trailing dot
			continue
		}
		l := len(lab)
		if l > 63 {
			// In real servers we should error; for simplicity, truncate to 63
			l = 63
			lab = lab[:63]
		}
		b = append(b, byte(l))
		b = append(b, lab...)
	}
	// Terminator label
	b = append(b, 0x00)
	return b
}

// appendNameCompressed encodes a DNS name using label compression per RFC 1035.
// nameOffsets maps domain suffixes to their offset in the message for reuse.
// appendNameCompressed encodes a domain name with DNS compression support,
// using compression pointers to reduce packet size when names are repeated.
func appendNameCompressed(b []byte, name string, nameOffsets map[string]int) []byte {
	// Root name
	if name == "" || name == "." {
		return append(b, 0)
	}
	// Work with lower-case for compression map consistency (DNS names are case-insensitive)
	labels := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	// We'll iterate through suffixes from left to right
	for i := 0; i < len(labels); i++ {
		suffix := strings.Join(labels[i:], ".")
		if off, ok := nameOffsets[suffix]; ok {
			// Write a compression pointer: 11xxxxxx xxxxxxxx (14-bit offset)
			// Ensure offset fits in 14 bits (it will in our small messages)
			ptr := 0xC000 | off
			b = append(b, byte(ptr>>8), byte(ptr))
			return b
		}
		// Record offset for this suffix at current position (before writing this label)
		nameOffsets[suffix] = len(b)
		// Write label length and bytes
		lab := labels[i]
		if lab == "" {
			continue
		}
		l := len(lab)
		if l > 63 {
			l = 63
			lab = lab[:63]
		}
		b = append(b, byte(l))
		b = append(b, lab...)
	}
	// End with zero-length label
	b = append(b, 0)
	return b
}

// serializeMessage converts a DNSMessage into wire bytes.
// Implements basic name compression during serialization.
// serializeMessage converts a DNSMessage struct to wire format bytes
// for transmission over UDP, following RFC 1035 packet structure.
func serializeMessage(m DNSMessage) []byte {
	var buf []byte
	nameOffsets := make(map[string]int)

	// Header: 6 x uint16 (12 bytes)
	buf = appendUint16(buf, m.Header.ID)
	buf = appendUint16(buf, m.Header.Flags)
	buf = appendUint16(buf, m.Header.QDCount)
	buf = appendUint16(buf, m.Header.ANCount)
	buf = appendUint16(buf, m.Header.NSCount)
	buf = appendUint16(buf, m.Header.ARCount)

	// Questions
	for _, q := range m.Questions {
		buf = appendNameCompressed(buf, q.Name, nameOffsets)
		buf = appendUint16(buf, q.Type)
		buf = appendUint16(buf, q.Class)
	}

	// Answers
	for _, rr := range m.Answers {
		buf = appendNameCompressed(buf, rr.Name, nameOffsets)
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		// RDLength is length of RData
		rdlen := uint16(len(rr.RData))
		buf = appendUint16(buf, rdlen)
		buf = append(buf, rr.RData...)
	}

	// Authorities (unused in this simple server)
	for _, rr := range m.Authorities {
		buf = appendNameCompressed(buf, rr.Name, nameOffsets)
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		rdlen := uint16(len(rr.RData))
		buf = appendUint16(buf, rdlen)
		buf = append(buf, rr.RData...)
	}

	// Additionals (unused in this simple server)
	for _, rr := range m.Additionals {
		buf = appendNameCompressed(buf, rr.Name, nameOffsets)
		buf = appendUint16(buf, rr.Type)
		buf = appendUint16(buf, rr.Class)
		buf = appendUint32(buf, rr.TTL)
		rdlen := uint16(len(rr.RData))
		buf = appendUint16(buf, rdlen)
		buf = append(buf, rr.RData...)
	}

	return buf
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
	m.Header.NSCount = uint16(len(m.Authorities))
	m.Header.ARCount = uint16(len(m.Additionals))
	// Echo the questions back in the response as per DNS behavior.
	m.Questions = query.Questions
	m.Answers = answers
	return m
}
