// Package main wires the malleable HTTP/HTTPS listeners into server startup.
//
// HTTP transport is opt-in and profile-driven: a server with no profile
// directory behaves exactly as it did before this transport existed. When the
// directory exists, a profile that cannot start is a startup error rather than a
// warning, because silently skipping it would leave an operator believing a
// listener was up while beacons failed to reach it.
package main

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// httpProfileReloadInterval is how often profile files are re-read. It is short
// enough that a URI rotation takes effect within a poll cycle, and long enough
// that it costs nothing measurable.
const httpProfileReloadInterval = 30 * time.Second

// httpProfileStore is the process-wide store backing all HTTP listeners.
var httpProfileStore *HTTPProfileStore

// activeHTTPListeners holds the running listeners so shutdown can stop them.
var activeHTTPListeners []*HTTPListener

// startHTTPListeners loads profiles and starts one listener per enabled profile.
// It returns the started listeners, or an error if any of them could not start.
func startHTTPListeners(cfg Config) ([]*HTTPListener, error) {
	if cfg.HTTPProfileDir == "" {
		return nil, nil
	}

	store := NewHTTPProfileStore(cfg.HTTPProfileDir)
	if err := store.Load(); err != nil {
		return nil, fmt.Errorf("failed to load HTTP profiles from %s: %w", cfg.HTTPProfileDir, err)
	}
	httpProfileStore = store

	profiles := store.List()
	if len(profiles) == 0 {
		LogInfo("HTTP transport: no profiles found in %s (disabled)", cfg.HTTPProfileDir)
		return nil, nil
	}

	var started []*HTTPListener
	for _, profile := range profiles {
		if !profile.Enabled {
			LogInfo("HTTP transport: profile %q is disabled, skipping", profile.Name)
			continue
		}

		listener, err := NewHTTPListener(profile, store, c2Manager, cfg.Debug)
		if err != nil {
			stopHTTPListeners(started)
			return nil, err
		}
		if err := listener.Start(); err != nil {
			stopHTTPListeners(started)
			return nil, err
		}

		started = append(started, listener)
	}

	if len(started) > 0 {
		go httpProfileReloadLoop(store)
		LogInfo("HTTP transport: %d listener(s) active, profiles hot-reload every %s",
			len(started), httpProfileReloadInterval)
	}

	return started, nil
}

// httpProfileReloadLoop picks up profile edits without a restart.
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
		}
	}
}

// stopHTTPListeners shuts listeners down, reporting any that refused to stop.
func stopHTTPListeners(listeners []*HTTPListener) {
	for _, listener := range listeners {
		if listener == nil {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := listener.Stop(ctx)
		cancel()
		if err != nil && !errors.Is(err, context.Canceled) {
			LogWarn("HTTP transport: listener %q did not stop cleanly: %v", listener.profileName, err)
		}
	}
}

// StopHTTPListeners stops every listener started by startHTTPListeners.
func StopHTTPListeners() {
	stopHTTPListeners(activeHTTPListeners)
	activeHTTPListeners = nil
}
