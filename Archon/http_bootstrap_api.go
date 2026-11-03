package main

import (
	"fmt"
	"net/http"
	"strings"
)

// defaultBootstrapPath is where a listener serves profile hand-offs unless its
// profile names a different place. It is deliberately short: it appears in a
// task string that may travel through DNS.
const defaultBootstrapPath = "/_p"

// buildHTTPProfileTask renders the short task a beacon receives when an operator
// adds an HTTP listener. url and token are separated by "|" so the client needs no
// JSON parser for this path.
func buildHTTPProfileTask(bootstrapURL, token, pin string) string {
	// <url>|<token>[|<pin>]. The pin is what lets the beacon verify the listener
	// it is being pointed at; without it the hand-off would trust any TLS
	// endpoint. A plain-HTTP listener has no pin, so the field is omitted rather
	// than trailing an empty separator.
	task := "http_profile:" + bootstrapURL + "|" + token
	if pin != "" {
		task += "|" + pin
	}
	return task
}

// parseHTTPProfileTask splits the task back into its parts. It returns ok=false
// for anything malformed, so a bad task never produces a half-applied transport.
func parseHTTPProfileTask(task string) (bootstrapURL, token string, ok bool) {
	const prefix = "http_profile:"
	if !strings.HasPrefix(task, prefix) {
		return "", "", false
	}
	rest := task[len(prefix):]
	sep := strings.LastIndex(rest, "|")
	if sep <= 0 || sep == len(rest)-1 {
		return "", "", false
	}
	return rest[:sep], rest[sep+1:], true
}

// bootstrapPathForSpec returns the path a beacon should call on this listener. A
// profile can move it (some deployments front the listener with something that
// rewrites paths); otherwise the default applies.
func bootstrapPathForSpec(spec HTTPListenerSpec) string {
	if path := strings.TrimSpace(spec.BootstrapPath); path != "" {
		if !strings.HasPrefix(path, "/") {
			path = "/" + path
		}
		return path
	}
	return defaultBootstrapPath
}

// bootstrapURLForListener builds the absolute URL a beacon will fetch its profile
// from: the listener's own scheme/host plus its bootstrap path.
func (api *APIServer) bootstrapURLForListener(spec HTTPListenerSpec) string {
	host := strings.TrimSpace(spec.Host)
	if host == "" {
		return ""
	}
	scheme := strings.ToLower(strings.TrimSpace(spec.Scheme))
	if scheme == "" {
		scheme = "https"
	}
	if scheme != "http" && scheme != "https" {
		return ""
	}
	// A host that already carries a scheme is used as-is by some profiles; trim it
	// so the URL cannot end up as https://https://host.
	host = strings.TrimPrefix(strings.TrimPrefix(host, "http://"), "https://")
	return fmt.Sprintf("%s://%s%s", scheme, host, bootstrapPathForSpec(spec))
}

// handleBootstrapProfile hands a beacon the profile an operator attached to it.
//
// Called by a listener, not by a beacon: the listener asks on the beacon's behalf
// with its own credentials, and this answers with the stored payload exactly once.
// The token is what authorises the hand-off, so a listener cannot enumerate other
// beacons' profiles.
func (api *APIServer) handleBootstrapProfile(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimSpace(r.URL.Query().Get("token"))
	if token == "" {
		token = strings.TrimSpace(r.URL.Query().Get("t"))
	}
	beaconID := strings.TrimSpace(r.URL.Query().Get("beacon_id"))

	if token == "" {
		api.sendError(w, http.StatusBadRequest, "token is required")
		return
	}

	payload, err := api.db.ConsumeHTTPProfileToken(token, beaconID)
	if err != nil {
		// Unknown, expired, already spent and wrong-beacon all look the same, which
		// is the point: probing the endpoint must not reveal which tokens exist.
		api.sendError(w, http.StatusNotFound, "bootstrap token is invalid or expired")
		return
	}

	api.sendSuccess(w, "bootstrap profile", map[string]interface{}{
		"token":   token,
		"payload": payload,
	})
}
