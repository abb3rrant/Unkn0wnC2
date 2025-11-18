package main

import (
	"errors"
	"strings"
)

/*
Reads 2 bytes at current offset (starts at 0 on new packet).
Interprets bytes as big-endian 16-bit signed integers (starting with largest bit).
Most fields are 16 bits and DNS uses big-endian on wire.
Inputs the bytes within the buffer, and the current place or offset.
Outputs the uint16 value, the new offset, and/or error.
*/
// readUint16 reads a 16-bit unsigned integer from a byte buffer at the specified offset,
// returning the value, new offset, and any error encountered.
func readUint16(buf []byte, off int) (uint16, int, error) {
	if off+2 > len(buf) {
		return 0, off, errors.New("short read: uint16 requires 2 bytes")
	}
	v := uint16(buf[off])<<8 | uint16(buf[off+1])
	return v, off + 2, nil
}

/*
Parses the fixed 12-byte DNS header at the start of a DNS message by reading six uint16 fields in order.
Inputs entire DNS message bytes as buf.
Outputs DNSHeader, next offset, and/or error
Flags field will still be packed.
*/
// ParseHeader extracts DNS header information from a packet buffer,
// returning the parsed header, bytes consumed, and any parsing error.
func ParseHeader(buf []byte) (DNSHeader, int, error) {
	off := 0
	var h DNSHeader
	var err error

	if h.ID, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	if h.Flags, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	if h.QDCount, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	if h.ANCount, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	if h.NSCount, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	if h.ARCount, off, err = readUint16(buf, off); err != nil {
		return DNSHeader{}, 0, err
	}
	return h, off, nil
}

// parseName parses a domain name at 'off' and returns the dotted name and the
// next offset in the original stream (handling compression pointers).
// parseName decodes a domain name from DNS wire format with compression support,
// returning the name, final offset, and any parsing error.
func parseName(buf []byte, off int) (string, int, error) {
	const hopLimit = 16 // guard against pointer loops

	parts := []string{} // collect labels
	cur := off          // cursor walking the name bytes
	next := off         // where caller continues after the name
	hopped := false     // true if we followed a compression pointer
	hops := 0

	for {
		if cur >= len(buf) {
			return "", off, errors.New("name: out of range")
		}
		b := buf[cur]

		if b == 0x00 {
			// End of name. Only advance 'next' if we never hopped (we're at original path).
			if !hopped {
				next = cur + 1
			}
			break
		}

		// Check for compression pointer: top two bits set (11xx xxxx)
		if b&0xC0 == 0xC0 {
			// Pointer consumes two bytes
			if cur+1 >= len(buf) {
				return "", off, errors.New("name: pointer truncated")
			}
			ptr := int(b&0x3F)<<8 | int(buf[cur+1])
			if ptr >= len(buf) {
				return "", off, errors.New("name: pointer target out of range")
			}
			// Only the first time we see a pointer do we advance 'next'
			if !hopped {
				next = cur + 2
			}
			cur = ptr
			hopped = true

			hops++
			if hops > hopLimit {
				return "", off, errors.New("name: too many pointer hops")
			}
			continue
		}

		// Otherwise it's a normal label: one length byte, then that many bytes of label
		labLen := int(b)
		cur++ // move past length byte

		if labLen == 0 {
			// Should have been caught by b == 0 case above, but keep defensive behavior
			if !hopped {
				next = cur
			}
			break
		}
		if cur+labLen > len(buf) {
			return "", off, errors.New("name: label truncated")
		}

		label := string(buf[cur : cur+labLen])
		parts = append(parts, label)

		cur += labLen
		if !hopped {
			next = cur
		}
	}

	name := strings.Join(parts, ".")
	return name, next, nil
}

// parseQuestion extracts a DNS question from the packet buffer,
// including the domain name, query type, and query class.
func parseQuestion(buf []byte, off int) (DNSQuestion, int, error) {
	var q DNSQuestion

	name, next, err := parseName(buf, off)
	if err != nil {
		return q, off, err
	}

	typ, next2, err := readUint16(buf, next)
	if err != nil {
		return q, off, err
	}

	class, next3, err := readUint16(buf, next2)
	if err != nil {
		return q, off, err
	}

	q.Name = name
	q.Type = typ
	q.Class = class

	return q, next3, nil
}

// parseMessage parses the full DNS message: header + questions (for now).
// Returns the parsed message and the final offset position.
// (removed duplicate parseMessage)

// parseMessage parses the full DNS message: header + questions (for now).
// Returns the parsed message and the final offset position.
// parseMessage parses a complete DNS message from a byte buffer,
// extracting the header and all question sections.
func parseMessage(buf []byte) (DNSMessage, int, error) {
	var m DNSMessage
	off := 0

	// 1) Header
	h, next, err := ParseHeader(buf)
	if err != nil {
		return m, 0, err
	}
	m.Header = h
	off = next

	// 2) Questions (QDCount)
	qd := int(h.QDCount)
	m.Questions = make([]DNSQuestion, 0, qd)
	for i := 0; i < qd; i++ {
		q, next, err := parseQuestion(buf, off)
		if err != nil {
			return m, 0, err
		}
		m.Questions = append(m.Questions, q)
		off = next
	}

	// 3) Answers (ANCount)
	an := int(h.ANCount)
	m.Answers = make([]DNSResourceRecord, 0, an)
	for i := 0; i < an; i++ {
		rr, next, err := parseResourceRecord(buf, off)
		if err != nil {
			return m, 0, err
		}
		m.Answers = append(m.Answers, rr)
		off = next
	}

	// 4) Authorities (NSCount)
	ns := int(h.NSCount)
	m.Authorities = make([]DNSResourceRecord, 0, ns)
	for i := 0; i < ns; i++ {
		rr, next, err := parseResourceRecord(buf, off)
		if err != nil {
			return m, 0, err
		}
		m.Authorities = append(m.Authorities, rr)
		off = next
	}

	// 5) Additionals (ARCount)
	ar := int(h.ARCount)
	m.Additionals = make([]DNSResourceRecord, 0, ar)
	for i := 0; i < ar; i++ {
		rr, next, err := parseResourceRecord(buf, off)
		if err != nil {
			return m, 0, err
		}
		m.Additionals = append(m.Additionals, rr)
		off = next
	}

	return m, off, nil
}

// parseResourceRecord parses a DNS resource record from the buffer, returning the record and new offset.
func parseResourceRecord(buf []byte, off int) (DNSResourceRecord, int, error) {
	var rr DNSResourceRecord

	name, next, err := parseName(buf, off)
	if err != nil {
		return rr, off, err
	}

	typ, next, err := readUint16(buf, next)
	if err != nil {
		return rr, off, err
	}

	class, next, err := readUint16(buf, next)
	if err != nil {
		return rr, off, err
	}

	ttlHigh, next, err := readUint16(buf, next)
	if err != nil {
		return rr, off, err
	}
	ttlLow, next, err := readUint16(buf, next)
	if err != nil {
		return rr, off, err
	}
	ttl := uint32(ttlHigh)<<16 | uint32(ttlLow)

	rdlen, next, err := readUint16(buf, next)
	if err != nil {
		return rr, off, err
	}
	end := next + int(rdlen)
	if end > len(buf) {
		return rr, off, errors.New("resource record truncated")
	}
	rdata := make([]byte, rdlen)
	copy(rdata, buf[next:end])

	rr.Name = name
	rr.Type = typ
	rr.Class = class
	rr.TTL = ttl
	rr.RDLength = rdlen
	rr.RData = rdata

	return rr, end, nil
}
