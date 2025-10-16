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
func readUint16(buf []byte, off int) (uint16, int, error) {
	if off+2 > len(buf) {
		return 0, off, errors.New("short read: uint16 requires 2 bytes")
	}
	v := uint16(buf[off])<<8 | uint16(buf[off+1])
	return v, off + 2, nil
}

/*
Reads 4 bytes at current offset, interprets as big-endian 32-bit signed integers.
Advances offset by 4. Some DNS fields are 32 bits on the wire.
Inputs bytes within buffer and current offset.
Outputs unint32 value, new offset, and/or error
*/
func readUint32(buf []byte, off int) (uint32, int, error) {
	if off+4 > len(buf) {
		return 0, off, errors.New("short read: uint32 requires 4 bytes")
	}
	v := uint32(buf[off])<<24 | uint32(buf[off+1])<<16 | uint32(buf[off+2])<<8 | uint32(buf[off+3])
	return v, off + 4, nil
}

/*
Returns a slice view of (n) number of bytes starting at the current offset and advances the offset by n.
Allows for pulling out variable-length segments without interpreting them yet.
Inputs bytes within buffer, offset, and n
Outputs a slice of the bytes, next offset, and/or error
Returns a view of the underlying buffer, not a copy
*/
func readBytes(buf []byte, off, n int) ([]byte, int, error) {
	if off+n > len(buf) {
		return nil, off, errors.New("short read: not enough bytes")
	}
	return buf[off : off+n], off + n, nil
}

/*
Parses the fixed 12-byte DNS header at the start of a DNS message by reading six uint16 fields in order.
Inputs entire DNS message bytes as buf.
Outputs DNSHeader, next offset, and/or error
Flags field will still be packed.
*/
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
	qd := int(h.QDCount) // cast from uint16 to int for loops/slices
	m.Questions = make([]DNSQuestion, 0, qd)

	for i := 0; i < qd; i++ {
		q, next, err := parseQuestion(buf, off)
		if err != nil {
			return m, 0, err
		}
		m.Questions = append(m.Questions, q)
		off = next
	}

	//add answers/authority/additional later.
	return m, off, nil
}
