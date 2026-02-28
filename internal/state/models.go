package state

// SyncRequest is the payload sent to POST /api/daemon/v1/sync.
type SyncRequest struct {
	HostID         string          `json:"host_id"`
	DaemonVersion  string          `json:"daemon_version,omitempty"`
	Status         HostStatus      `json:"status"`
	Observed       []Observed      `json:"observed"`
	DiscoveredKeys []DiscoveredKey `json:"discovered_keys,omitempty"`
}

// HostStatus reports the daemon's current state.
type HostStatus struct {
	LastApplyResult     string  `json:"last_apply_result"` // "success", "failure", "pending"
	DriftDetected       bool    `json:"drift_detected"`
	AppliedAt           *string `json:"applied_at,omitempty"`
	PasswordAuthBlocked *bool   `json:"password_auth_blocked,omitempty"`
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
	Config             *SyncConfig     `json:"config,omitempty"`
}

// SyncConfig carries configuration directives from the control plane.
type SyncConfig struct {
	ManagedUsers []ConfigUser `json:"managed_users"`
	PollSeconds  int          `json:"poll_seconds"`
}

// ConfigUser describes an OS user the daemon should manage.
type ConfigUser struct {
	OSUser             string `json:"os_user"`
	AuthorizedKeysPath string `json:"authorized_keys_path,omitempty"`
	ExclusiveKeys      bool   `json:"exclusive_keys"`
}

// HostPolicy contains policy directives from the server.
type HostPolicy struct {
	PollSeconds       int        `json:"poll_seconds"`
	BlockPasswordAuth bool       `json:"block_password_auth"`
	EnforceIPBinding  bool       `json:"enforce_ip_binding"`
	BreakGlass        BreakGlass `json:"break_glass"`
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
	ExclusiveKeys  bool            `json:"exclusive_keys"`
}

// AuthorizedKey is a single SSH public key to be placed in authorized_keys.
type AuthorizedKey struct {
	KeyID             string `json:"key_id"`
	FingerprintSHA256 string `json:"fingerprint_sha256"`
	PublicKey         string `json:"public_key"`
}

// DiscoveredKey represents an existing SSH public key found in a user's
// authorized_keys file during registration. The control plane uses these
// to import pre-existing keys and auto-assign them to the host user.
type DiscoveredKey struct {
	OSUser    string `json:"os_user"`
	PublicKey string `json:"public_key"`
}

// RegisterRequest is the payload sent to POST /api/daemon/v1/register.
type RegisterRequest struct {
	EnrollmentToken string          `json:"enrollment_token"`
	Host            HostInfo        `json:"host"`
	ManagedUsers    []UserEntry     `json:"managed_users"`
	DiscoveredKeys  []DiscoveredKey `json:"discovered_keys,omitempty"`
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
	FirstSyncSeconds       int          `json:"first_sync_seconds"`
	ManagedBlockMarkers    BlockMarkers `json:"managed_block_markers"`
}

// BlockMarkers are the comment strings that delimit the managed section.
type BlockMarkers struct {
	Begin string `json:"begin"`
	End   string `json:"end"`
}
