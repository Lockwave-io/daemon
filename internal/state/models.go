package state

// SyncRequest is the payload sent to POST /api/daemon/v1/sync.
type SyncRequest struct {
	HostID        string     `json:"host_id"`
	DaemonVersion string     `json:"daemon_version,omitempty"`
	Status        HostStatus `json:"status"`
	Observed      []Observed `json:"observed"`
}

// HostStatus reports the daemon's current state.
type HostStatus struct {
	LastApplyResult string  `json:"last_apply_result"` // "success", "failure", "pending"
	DriftDetected   bool    `json:"drift_detected"`
	AppliedAt       *string `json:"applied_at,omitempty"`
}

// Observed reports what the daemon sees in a managed authorized_keys file.
type Observed struct {
	OSUser                  string   `json:"os_user"`
	ManagedBlockPresent     bool     `json:"managed_block_present"`
	ManagedKeysFingerprints []string `json:"managed_keys_fingerprints"`
}

// SyncResponse is the response from POST /api/daemon/v1/sync.
type SyncResponse struct {
	ServerTime         string          `json:"server_time"`
	HostPolicy         HostPolicy      `json:"host_policy"`
	DesiredState       []DesiredState  `json:"desired_state"`
	CredentialRotation *string         `json:"credential_rotation"`
	Update             *UpdateHint     `json:"update,omitempty"`
}

// UpdateHint tells the daemon a newer version is available and where to download it.
type UpdateHint struct {
	Version  string `json:"version"`
	URL      string `json:"url"`
	Checksum string `json:"checksum,omitempty"` // SHA-256 hex digest of the binary
}

// HostPolicy contains policy directives from the server.
type HostPolicy struct {
	PollSeconds int        `json:"poll_seconds"`
	BreakGlass  BreakGlass `json:"break_glass"`
}

// BreakGlass indicates whether emergency lockout is active.
type BreakGlass struct {
	Active bool    `json:"active"`
	Scope  *string `json:"scope"`
}

// DesiredState represents the authorized keys for a single OS user.
type DesiredState struct {
	OSUser         string          `json:"os_user"`
	AuthorizedKeys []AuthorizedKey `json:"authorized_keys"`
}

// AuthorizedKey is a single SSH public key to be placed in authorized_keys.
type AuthorizedKey struct {
	KeyID             string `json:"key_id"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	PublicKey         string `json:"public_key"`
}

// RegisterRequest is the payload sent to POST /api/daemon/v1/register.
type RegisterRequest struct {
	EnrollmentToken string       `json:"enrollment_token"`
	Host            HostInfo     `json:"host"`
	ManagedUsers    []UserEntry  `json:"managed_users"`
}

// HostInfo describes the host being registered.
type HostInfo struct {
	Hostname      string `json:"hostname"`
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	DaemonVersion string `json:"daemon_version"`
	IP            string `json:"ip"`
}

// UserEntry is an OS user to be managed during registration.
type UserEntry struct {
	OSUser             string `json:"os_user"`
	AuthorizedKeysPath string `json:"authorized_keys_path,omitempty"`
}

// RegisterResponse is the response from POST /api/daemon/v1/register.
type RegisterResponse struct {
	HostID     string `json:"host_id"`
	Credential string `json:"credential"`
	Policy     Policy `json:"policy"`
	ServerTime string `json:"server_time"`
}

// Policy contains initial configuration from the server.
type Policy struct {
	MinPollSeconds         int          `json:"min_poll_seconds"`
	RecommendedPollSeconds int          `json:"recommended_poll_seconds"`
	ManagedBlockMarkers    BlockMarkers `json:"managed_block_markers"`
}

// BlockMarkers are the comment strings that delimit the managed section.
type BlockMarkers struct {
	Begin string `json:"begin"`
	End   string `json:"end"`
}
