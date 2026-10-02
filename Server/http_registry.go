// Package main keeps the running HTTP listeners in step with the profiles that
// Archon assigns to this DNS server.
//
// The registry exists so a profile is applied without an operator touching this
// host: Archon assigns a profile, the server is told, and listeners are started,
// restarted or stopped to match. Profiles loaded from a local directory still work
// for a server that has no control plane, but an assigned profile wins over a file
// of the same name.
package main

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"time"
)

// listenerBinding is the part of a profile that a running listener cannot change
// without being rebound. Profile *content* changes (URIs, status codes, headers,
// jitter) are picked up live, because every request reads the current profile from
// the store; only these need a restart.
type listenerBinding struct {
	Addr       string
	Scheme     string
	CertFile   string
	KeyFile    string
	MinVersion string
	Pin        string
}

// bindingFor extracts the binding-sensitive fields of a profile.
func bindingFor(profile *HTTPProfile) listenerBinding {
	return listenerBinding{
		Addr:       profile.ListenerAddr(),
		Scheme:     profile.Scheme,
		CertFile:   profile.TLS.CertFile,
		KeyFile:    profile.TLS.KeyFile,
		MinVersion: profile.TLS.MinVersion,
		Pin:        profile.TLS.SPKISHA256,
	}
}

// runningListener is one started listener and the profile version it was started
// from.
type runningListener struct {
	listener *HTTPListener
	binding  listenerBinding
}

// HTTPListenerStatus is what this server reports about a profile so the operators'
// listener page can show reality rather than intent.
type HTTPListenerStatus struct {
	Name    string `json:"name"`
	Addr    string `json:"addr"`
	Scheme  string `json:"scheme"`
	Source  string `json:"source"`
	Running bool   `json:"running"`
	Enabled bool   `json:"enabled"`
	Error   string `json:"error,omitempty"`
}

// ReconcileResult summarizes one pass, for logging and for the caller to report.
type ReconcileResult struct {
	Started   []string
	Restarted []string
	Stopped   []string
	Failed    []string
}

// Changed reports whether anything happened worth logging.
func (r ReconcileResult) Changed() bool {
	return len(r.Started)+len(r.Restarted)+len(r.Stopped)+len(r.Failed) > 0
}

// HTTPRegistry owns the running listeners.
type HTTPRegistry struct {
	store *HTTPProfileStore
	c2    *C2Manager
	debug bool

	mu       sync.Mutex
	running  map[string]*runningListener
	failures map[string]string
}

// NewHTTPRegistry creates a registry over a profile store.
func NewHTTPRegistry(store *HTTPProfileStore, c2 *C2Manager, debug bool) *HTTPRegistry {
	return &HTTPRegistry{
		store:    store,
		c2:       c2,
		debug:    debug,
		running:  make(map[string]*runningListener),
		failures: make(map[string]string),
	}
}

// Store exposes the underlying store, for the file reload ticker.
func (r *HTTPRegistry) Store() *HTTPProfileStore {
	return r.store
}

// ApplyRemote installs the profiles Archon assigns to this server and reconciles.
//
// Removal is driven by absence: any currently remote profile that is not in the new
// set is dropped, which is what makes detaching a profile in the UI actually stop a
// listener here.
func (r *HTTPRegistry) ApplyRemote(profiles []*HTTPProfile) (ReconcileResult, error) {
	assigned := make(map[string]bool, len(profiles))

	var firstErr error
	for _, profile := range profiles {
		if err := r.store.UpsertRemote(profile); err != nil {
			// One unusable profile must not stop the others being applied, but it
			// is reported so the operator sees it rather than wondering why a
			// listener never appeared.
			logf("[HTTP] %v", err)
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		assigned[profile.Name] = true
	}

	for _, name := range r.store.RemoteNames() {
		if assigned[name] {
			continue
		}
		// No longer assigned: drop it and let reconcile stop its listener.
		r.store.RemoveRemote(name)
		logf("[HTTP] Profile %q is no longer assigned; its listener will be stopped", name)
	}

	result := r.Reconcile()

	// A profile that validated but could not start (a port already in use, a
	// certificate absent) leaves the assignment only partly applied. Reporting that
	// as an error is what surfaces it to the control plane, while the listeners that
	// did start keep serving.
	if firstErr == nil && len(result.Failed) > 0 {
		firstErr = fmt.Errorf("assignment applied with %d failure(s): %v", len(result.Failed), result.Failed)
	}

	return result, firstErr
}

// Reconcile makes the running listeners match the enabled profiles in the store.
func (r *HTTPRegistry) Reconcile() ReconcileResult {
	var result ReconcileResult

	profiles := r.store.List()
	wanted := make(map[string]*HTTPProfile, len(profiles))

	for _, profile := range profiles {
		if !profile.Enabled {
			continue
		}
		wanted[profile.Name] = profile
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Start or restart what should be running.
	names := make([]string, 0, len(wanted))
	for name := range wanted {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		profile := wanted[name]
		binding := bindingFor(profile)

		current, isRunning := r.running[name]
		if isRunning && current.binding == binding {
			// Content changes are already live through the store.
			continue
		}

		if isRunning {
			// Something the socket depends on changed, so rebind.
			r.stopLocked(name)
			if err := r.startLocked(profile); err != nil {
				result.Failed = append(result.Failed, name)
				continue
			}
			result.Restarted = append(result.Restarted, name)
			continue
		}

		if err := r.startLocked(profile); err != nil {
			result.Failed = append(result.Failed, name)
			continue
		}
		result.Started = append(result.Started, name)
	}

	// Stop anything running that is gone or disabled.
	runningNames := make([]string, 0, len(r.running))
	for name := range r.running {
		runningNames = append(runningNames, name)
	}
	sort.Strings(runningNames)

	for _, name := range runningNames {
		if _, keep := wanted[name]; keep {
			continue
		}
		r.stopLocked(name)
		result.Stopped = append(result.Stopped, name)
	}

	for _, name := range result.Started {
		logf("[HTTP] Started listener %q", name)
	}
	for _, name := range result.Restarted {
		logf("[HTTP] Restarted listener %q after a bind or TLS change", name)
	}
	for _, name := range result.Stopped {
		logf("[HTTP] Stopped listener %q", name)
	}
	for _, name := range result.Failed {
		logf("[HTTP] Listener %q failed: %s", name, r.failures[name])
	}

	return result
}

// startLocked starts a listener for a profile. Caller holds r.mu.
func (r *HTTPRegistry) startLocked(profile *HTTPProfile) error {
	listener, err := NewHTTPListener(profile, r.store, r.c2, r.debug)
	if err != nil {
		// A profile that will not construct (a certificate that does not match its
		// pin, for instance) is remembered so the operator sees why a listener the
		// UI claims is assigned is not running.
		r.failures[profile.Name] = err.Error()
		return err
	}
	if err := listener.Start(); err != nil {
		r.failures[profile.Name] = err.Error()
		return err
	}

	delete(r.failures, profile.Name)
	r.running[profile.Name] = &runningListener{
		listener: listener,
		binding:  bindingFor(profile),
	}
	return nil
}

// stopLocked stops a listener. Caller holds r.mu.
func (r *HTTPRegistry) stopLocked(name string) {
	current, ok := r.running[name]
	if !ok {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := current.listener.Stop(ctx); err != nil {
		logf("[HTTP] Listener %q did not stop cleanly: %v", name, err)
	}
	delete(r.running, name)
}

// Status reports every profile this server knows about and whether it is serving.
func (r *HTTPRegistry) Status() []HTTPListenerStatus {
	r.mu.Lock()
	defer r.mu.Unlock()

	statuses := []HTTPListenerStatus{}

	for _, profile := range r.store.List() {
		status := HTTPListenerStatus{
			Name:    profile.Name,
			Scheme:  profile.Scheme,
			Source:  r.store.Source(profile.Name),
			Enabled: profile.Enabled,
			Addr:    profile.ListenerAddr(),
		}
		if running, ok := r.running[profile.Name]; ok {
			status.Running = true
			status.Addr = running.listener.Addr()
		}
		if message, ok := r.failures[profile.Name]; ok {
			status.Error = message
		}
		statuses = append(statuses, status)
	}

	sort.Slice(statuses, func(i, j int) bool { return statuses[i].Name < statuses[j].Name })
	return statuses
}

// Shutdown stops every running listener.
func (r *HTTPRegistry) Shutdown() {
	r.mu.Lock()
	defer r.mu.Unlock()

	names := make([]string, 0, len(r.running))
	for name := range r.running {
		names = append(names, name)
	}
	for _, name := range names {
		r.stopLocked(name)
	}
}

// watchdogInterval is how often the registry reconciles without new input. It
// catches a listener that died for a reason outside the profile set.
const watchdogInterval = 60 * time.Second

// Watch starts a background reconciler. It returns immediately.
func (r *HTTPRegistry) Watch() {
	go func() {
		ticker := time.NewTicker(watchdogInterval)
		defer ticker.Stop()
		for range ticker.C {
			// Catches a listener that died, and retries one that could not start
			// because its certificate or port was not ready yet. The resulting
			// state reaches the control plane through Status() on the next report.
			r.Reconcile()
		}
	}()
}

// Describe renders a one-line summary for the startup log.
func (r *HTTPRegistry) Describe() string {
	statuses := r.Status()
	running := 0
	for _, status := range statuses {
		if status.Running {
			running++
		}
	}
	return fmt.Sprintf("%d profile(s), %d listener(s) running", len(statuses), running)
}
