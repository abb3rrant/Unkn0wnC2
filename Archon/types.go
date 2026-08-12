package main

import "encoding/json"

// Beacon represents a registered beacon/implant.
type Beacon struct {
	ID                string       `json:"id"`
	Hostname          string       `json:"hostname"`
	Username          string       `json:"username"`
	OS                string       `json:"os"`
	Arch              string       `json:"arch"`
	IPAddress         string       `json:"ip_address"`
	DNSServerID       string       `json:"dns_server_id"`
	FirstSeen         string       `json:"first_seen"`
	LastSeen          string       `json:"last_seen"`
	Status            string       `json:"status"`
	BeaconName        string       `json:"beacon_name"`
	PayloadFormat     string       `json:"payload_format"`
	Encoding          string       `json:"encoding"`
	BuildID           string       `json:"build_id"`
	RegistrationStage *int         `json:"registration_stage,omitempty"`
	BuildConfig       *BuildConfig `json:"build_config,omitempty"`
}

// DNSServer represents a registered DNS server in the Shadow Mesh.
type DNSServer struct {
	ID          string `json:"id"`
	Domain      string `json:"domain"`
	Address     string `json:"address"`
	Status      string `json:"status"`
	FirstSeen   string `json:"first_seen"`
	LastCheckin string `json:"last_checkin"`
	BeaconCount int    `json:"beacon_count"`
	TaskCount   int    `json:"task_count"`
}

// Task represents a task in the task queue.
type Task struct {
	ID          string        `json:"id"`
	BeaconID    string        `json:"beacon_id"`
	Command     string        `json:"command"`
	Status      string        `json:"status"`
	CreatedBy   string        `json:"created_by,omitempty"`
	CreatedAt   string        `json:"created_at,omitempty"`
	SentAt      string        `json:"sent_at,omitempty"`
	CompletedAt string        `json:"completed_at,omitempty"`
	Result      string        `json:"result,omitempty"`
	ResultSize  int           `json:"result_size,omitempty"`
	Progress    *TaskProgress `json:"progress,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`
	Username    string        `json:"username,omitempty"`
	OS          string        `json:"os,omitempty"`
}

// TaskProgress represents the exfiltration progress of a task result.
type TaskProgress struct {
	TaskID         string `json:"task_id"`
	ReceivedChunks int    `json:"received_chunks"`
	TotalChunks    int    `json:"total_chunks"`
	Progress       int    `json:"progress"`
	Status         string `json:"status"`
}

// DNSContact represents a beacon's contact history with a DNS server.
type DNSContact struct {
	DNSServerID  string `json:"dns_server_id"`
	DNSDomain    string `json:"dns_domain"`
	FirstContact string `json:"first_contact"`
	LastContact  string `json:"last_contact"`
	ContactCount int64  `json:"contact_count"`
	DNSStatus    string `json:"dns_status"`
}

// Operator represents an authenticated operator/user.
type Operator struct {
	ID         string  `json:"id"`
	Username   string  `json:"username"`
	Role       string  `json:"role"`
	Email      string  `json:"email"`
	CreatedAt  string  `json:"created_at"`
	LoginCount int64   `json:"login_count"`
	IsActive   bool    `json:"is_active"`
	LastLogin  *string `json:"last_login"`
}

// StagerSession represents a stager binary delivery session.
type StagerSession struct {
	ID             string `json:"id"`
	StagerIP       string `json:"stager_ip"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	TotalChunks    int    `json:"total_chunks"`
	ChunksDelivered int   `json:"chunks_delivered"`
	CreatedAt      int64  `json:"created_at"`
	LastActivity   int64  `json:"last_activity"`
	Completed      bool   `json:"completed"`
	InitiatedByDNS string `json:"initiated_by_dns,omitempty"`
	CompletedAt    *int64 `json:"completed_at,omitempty"`
	ClientFilename string `json:"client_filename,omitempty"`
	ClientVersion  string `json:"client_version,omitempty"`
}

// ClientBinary represents a compiled client binary stored for stager delivery.
type ClientBinary struct {
	ID             string `json:"id"`
	Filename       string `json:"filename"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	Version        string `json:"version"`
	OriginalSize   int    `json:"original_size"`
	CompressedSize int    `json:"compressed_size"`
	Base64Size     int    `json:"base64_size"`
	ChunkSize      int    `json:"chunk_size"`
	TotalChunks    int    `json:"total_chunks"`
	DNSDomains     string `json:"dns_domains"`
	CreatedAt      int64  `json:"created_at"`
	CreatedBy      string `json:"created_by"`
}

// BeaconDomain represents a domain associated with a beacon for Shadow Mesh.
type BeaconDomain struct {
	Domain string `json:"domain"`
	Active bool   `json:"active"`
}

// DatabaseStats holds aggregate counts for the dashboard.
type DatabaseStats struct {
	DNSServers              int            `json:"dns_servers"`
	ActiveDNSServers        int            `json:"active_dns_servers"`
	Beacons                 int            `json:"beacons"`
	ActiveBeacons           int            `json:"active_beacons"`
	Tasks                   int            `json:"tasks"`
	TasksByStatus           map[string]int `json:"tasks_by_status,omitempty"`
	Operators               int            `json:"operators"`
	RecentAuditEvents       int            `json:"recent_audit_events"`
	StagerSessions          int            `json:"stager_sessions"`
	CompletedStagerSessions int            `json:"completed_stager_sessions"`
	ExfilTransfers          int            `json:"exfil_transfers"`
	CompletedExfilTransfers int            `json:"completed_exfil_transfers"`
}

// DNSServerBeacon represents a beacon as seen by a specific DNS server.
type DNSServerBeacon struct {
	BeaconID  string `json:"beacon_id"`
	Hostname  string `json:"hostname"`
	LastSeen  string `json:"last_seen"`
	Status    string `json:"status"`
	IPAddress string `json:"ip_address"`
}

// BeaconDNSConnection represents a connection between a beacon and a DNS server.
type BeaconDNSConnection struct {
	BeaconID    string `json:"beacon_id"`
	DNSServerID string `json:"dns_server_id"`
}

// CompletedTaskSync represents a completed task for DNS server sync.
// JSON tag must be "id" to match Server's TaskResponse struct.
type CompletedTaskSync struct {
	TaskID   string `json:"id"`
	BeaconID string `json:"beacon_id"`
	Status   string `json:"status"`
}

// StagerChunkAssignment represents a stager chunk assigned to a DNS server.
type StagerChunkAssignment struct {
	ChunkIndex int    `json:"chunk_index"`
	ChunkData  string `json:"chunk_data"`
}

// PendingStagerCache represents a pending stager cache entry for a DNS server.
type PendingStagerCache struct {
	ID             int      `json:"id"`
	ClientBinaryID string   `json:"client_binary_id"`
	TotalChunks    int      `json:"total_chunks"`
	Chunks         []string `json:"chunks"`
}

// DNSServerTask represents a task prepared for delivery by a DNS server.
type DNSServerTask struct {
	ID       string `json:"id"`
	BeaconID string `json:"beacon_id"`
	Command  string `json:"command"`
	Status   string `json:"status"`
}

// BuildConfig represents a beacon's build-time configuration.
// Extra keys are flattened into the top-level JSON to match the frontend contract.
type BuildConfig struct {
	BinaryID   string                 `json:"-"`
	BuildID    string                 `json:"-"`
	OS         string                 `json:"-"`
	Arch       string                 `json:"-"`
	DNSDomains string                 `json:"-"`
	CreatedAt  string                 `json:"-"`
	Extra      map[string]interface{} `json:"-"`
}

func (bc BuildConfig) MarshalJSON() ([]byte, error) {
	m := map[string]interface{}{
		"binary_id":  bc.BinaryID,
		"build_id":   bc.BuildID,
		"os":         bc.OS,
		"arch":       bc.Arch,
		"dns_domains": bc.DNSDomains,
		"created_at": bc.CreatedAt,
	}
	for k, v := range bc.Extra {
		m[k] = v
	}
	return json.Marshal(m)
}

// ExfilClientBuild represents a compiled exfil client binary.
type ExfilClientBuild struct {
	ID            string `json:"id"`
	Filename      string `json:"filename"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	CreatedAt     int64  `json:"created_at"`
	CreatedBy     string `json:"created_by"`
	FileSize      int64  `json:"file_size"`
	DNSDomains    string `json:"dns_domains"`
	DownloadPath  string `json:"download_path,omitempty"`
}

// BuildPhaseConfig holds per-phase malleable C2 settings resolved from a build.
type BuildPhaseConfig struct {
	RegistrationPhase map[string]interface{} `json:"registration_phase,omitempty"`
	PollPhase         map[string]interface{} `json:"poll_phase,omitempty"`
	DataExfilPhase    map[string]interface{} `json:"data_exfil_phase,omitempty"`
}
