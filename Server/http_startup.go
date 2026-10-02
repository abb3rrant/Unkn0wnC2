// Package main wires the HTTP/HTTPS transport into server startup and keeps it in
// step with the control plane.
//
// Two sources of profiles exist, and they are treated differently on purpose:
//
//   - Profiles in the local profile directory are this host's own configuration. A
//     profile that cannot start is a startup error, because the operator put it
//     there and needs to know immediately.
//   - Profiles assigned by Archon belong to the control plane. One that cannot start
//     is recorded and reported, never fatal: this process is first of all a DNS
//     server, and it must keep answering DNS even if an assigned listener is
//     unusable.
package main

import (
	"fmt"
	"time"
)

const (
	// httpProfileReloadInterval is how often profile files are re-read. Short
	// enough that a URI rotation takes effect within a poll cycle, and long enough
	// that it costs nothing measurable.
	httpProfileReloadInterval = 30 * time.Second

	// httpControlPlaneSyncInterval is how often assigned profiles are fetched.
	httpControlPlaneSyncInterval = 60 * time.Second

	// httpControlPlaneFirstSyncDelay lets the master client connect before the first
	// fetch, since startup begins the transport before the link to Archon is up.
	httpControlPlaneFirstSyncDelay = 10 * time.Second
)

// httpRegistry owns the running listeners, once startup has begun.
var httpRegistry *HTTPRegistry

// startHTTPTransport loads local profiles, starts a listener per enabled profile,
// and begins the reconcilers. HTTP transport is opt-in: no configured profile
// directory means the server runs DNS-only, exactly as before.
func startHTTPTransport(cfg Config) error {
	if cfg.HTTPProfileDir == "" {
		return nil
	}

	store := NewHTTPProfileStore(cfg.HTTPProfileDir)
	if err := store.Load(); err != nil {
		// A local profile that does not parse or validate is the operator's own
		// configuration being wrong, so it stops startup.
		return fmt.Errorf("failed to load HTTP profiles from %s: %w", cfg.HTTPProfileDir, err)
	}

	httpRegistry = NewHTTPRegistry(store, c2Manager, cfg.Debug)

	result := httpRegistry.Reconcile()
	if failed := failedFileProfiles(store, result); len(failed) > 0 {
		httpRegistry.Shutdown()
		httpRegistry = nil
		return fmt.Errorf("local HTTP profile(s) could not start: %v", failed)
	}

	if len(store.List()) == 0 {
		LogInfo("HTTP transport: no local profiles in %s; waiting on the control plane", cfg.HTTPProfileDir)
	} else {
		LogInfo("HTTP transport: %s", httpRegistry.Describe())
	}

	httpRegistry.Watch()
	go httpProfileReloadLoop(store)
	go httpControlPlaneSyncLoop(cfg)

	return nil
}

// failedFileProfiles returns the locally-configured profiles that failed to start.
// Assigned profiles are excluded: those are reported through the checkin state
// instead, so an unusable assignment cannot stop the server.
func failedFileProfiles(store *HTTPProfileStore, result ReconcileResult) []string {
	var failed []string
	for _, name := range result.Failed {
		if store.Source(name) == profileSourceFile {
			failed = append(failed, name)
		}
	}
	return failed
}

// httpProfileReloadLoop picks up edits to local profile files without a restart.
func httpProfileReloadLoop(store *HTTPProfileStore) {
	ticker := time.NewTicker(httpProfileReloadInterval)
	defer ticker.Stop()

	for range ticker.C {
		applied, rejected := store.Reload()
		if rejected > 0 {
			LogWarn("HTTP transport: %d profile edit(s) rejected, previous versions still live", rejected)
		}
		if applied > 0 {
			LogInfo("HTTP transport: %d profile(s) hot-reloaded", applied)
			// A reload can change a profile's enabled flag or a field the socket
			// depends on, which only the reconciler can act on.
			if httpRegistry != nil {
				httpRegistry.Reconcile()
			}
		}
	}
}

// httpControlPlaneSyncLoop fetches assigned profiles on an interval.
func httpControlPlaneSyncLoop(cfg Config) {
	timer := time.NewTimer(httpControlPlaneFirstSyncDelay)
	defer timer.Stop()

	for {
		<-timer.C
		SyncHTTPProfilesFromControlPlane(cfg)
		timer.Reset(httpControlPlaneSyncInterval)
	}
}

// SyncHTTPProfilesFromControlPlane fetches the profiles Archon assigns to this
// server and applies them.
//
// A failed fetch is not an error state: the last known assignment stays in force, so
// a control-plane outage does not tear down working listeners.
func SyncHTTPProfilesFromControlPlane(cfg Config) {
	registry := httpRegistry
	if registry == nil || masterClient == nil {
		return
	}

	profiles, err := masterClient.FetchHTTPProfiles()
	if err != nil {
		LogWarn("HTTP transport: could not fetch assigned profiles: %v", err)
		return
	}

	result, applyErr := registry.ApplyRemote(profiles)
	if applyErr != nil {
		LogWarn("HTTP transport: %v", applyErr)
	}
	if cfg.Debug || result.Changed() {
		LogInfo("HTTP transport after sync: %s", registry.Describe())
	}
}

// StopHTTPListeners stops every listener the registry started.
func StopHTTPListeners() {
	if httpRegistry == nil {
		return
	}
	httpRegistry.Shutdown()
	httpRegistry = nil
}
