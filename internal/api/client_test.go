package api

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/lockwave-io/daemon/internal/authorizedkeys"
	"github.com/lockwave-io/daemon/internal/config"
	"github.com/lockwave-io/daemon/internal/state"
	"github.com/lockwave-io/daemon/internal/telemetry"
)

// generateTestPublicKey returns a valid authorized_keys-format line for a
// freshly generated ed25519 key with the given comment.
func generateTestPublicKey(t *testing.T, comment string) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate ed25519 key: %v", err)
	}
	pub, err := ssh.NewPublicKey(priv.Public())
	if err != nil {
		t.Fatalf("ssh.NewPublicKey: %v", err)
	}
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestRegister_Success(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/daemon/v1/register" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("unexpected method: %s", r.Method)
		}

		var req state.RegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode request: %v", err)
		}

		if req.EnrollmentToken != "test-token-value" {
			t.Errorf("token = %q", req.EnrollmentToken)
		}
		if req.Host.Hostname != "test-host" {
			t.Errorf("hostname = %q", req.Host.Hostname)
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(state.RegisterResponse{
			HostID:     "host-uuid-123",
			Credential: "secret-credential-64chars-" + strings.Repeat("x", 38),
			Policy: state.Policy{
				MinPollSeconds:         30,
				RecommendedPollSeconds: 60,
				ManagedBlockMarkers: state.BlockMarkers{
					Begin: "# --- BEGIN LOCKWAVE MANAGED BLOCK ---",
					End:   "# --- END LOCKWAVE MANAGED BLOCK ---",
				},
			},
			ServerTime: "2026-02-26T12:00:00Z",
		})
	}))
	defer server.Close()

	logger := telemetry.NewLogger(true)
	ctx := context.Background()

	resp, err := Register(ctx, server.URL, "test-token-value", state.HostInfo{
		Hostname:      "test-host",
		OS:            "linux",
		Arch:          "x86_64",
		DaemonVersion: "1.0.0",
		IP:            "10.0.0.1",
	}, []state.UserEntry{{OSUser: "deploy"}}, nil, logger)

	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if resp.HostID != "host-uuid-123" {
		t.Errorf("host_id = %q", resp.HostID)
	}
	if resp.Policy.MinPollSeconds != 30 {
		t.Errorf("min_poll_seconds = %d", resp.Policy.MinPollSeconds)
	}
}

func TestRegister_SendsAuthorizedKeysPath(t *testing.T) {
	var capturedReq state.RegisterRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&capturedReq); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(state.RegisterResponse{
			HostID:     "host-1",
			Credential: "secret-64chars-" + strings.Repeat("x", 48),
			Policy: state.Policy{
				MinPollSeconds:         30,
				RecommendedPollSeconds: 60,
				ManagedBlockMarkers:    state.BlockMarkers{Begin: "# begin", End: "# end"},
			},
			ServerTime: "2026-02-26T12:00:00Z",
		})
	}))
	defer server.Close()

	logger := telemetry.NewLogger(true)
	users := []state.UserEntry{
		{OSUser: "deploy"},
		{OSUser: "www-data", AuthorizedKeysPath: "/var/www/.ssh/authorized_keys"},
	}

	_, err := Register(context.Background(), server.URL, "token", state.HostInfo{
		Hostname: "h", OS: "linux", Arch: "x86_64", DaemonVersion: "1.0.0", IP: "1.2.3.4",
	}, users, nil, logger)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if len(capturedReq.ManagedUsers) != 2 {
		t.Fatalf("managed_users count = %d, want 2", len(capturedReq.ManagedUsers))
	}
	if capturedReq.ManagedUsers[0].AuthorizedKeysPath != "" {
		t.Errorf("first user authorized_keys_path = %q, want empty", capturedReq.ManagedUsers[0].AuthorizedKeysPath)
	}
	if capturedReq.ManagedUsers[1].AuthorizedKeysPath != "/var/www/.ssh/authorized_keys" {
		t.Errorf("second user authorized_keys_path = %q", capturedReq.ManagedUsers[1].AuthorizedKeysPath)
	}
}

func TestRegister_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_, _ = w.Write([]byte(`{"error":"Invalid token"}`))
	}))
	defer server.Close()

	logger := telemetry.NewLogger(true)
	ctx := context.Background()

	_, err := Register(ctx, server.URL, "bad-token", state.HostInfo{
		Hostname: "h", OS: "linux", Arch: "x86_64", DaemonVersion: "1.0.0", IP: "1.2.3.4",
	}, []state.UserEntry{{OSUser: "u"}}, nil, logger)

	if err == nil {
		t.Error("expected error for invalid token")
	}
}

func TestSync_DesiredStateApplied(t *testing.T) {
	// Mock server returns desired state with one key
	credential := "test-secret-credential"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify headers are present (we don't validate HMAC in this test)
		if r.Header.Get("X-Daemon-Signature") == "" {
			t.Error("missing signature header")
		}
		if r.Header.Get("X-Daemon-Host-Id") != "host-1" {
			t.Errorf("host-id = %q", r.Header.Get("X-Daemon-Host-Id"))
		}

		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(state.SyncResponse{
			ServerTime: "2026-02-26T12:00:00Z",
			HostPolicy: state.HostPolicy{
				PollSeconds: 60,
				BreakGlass:  state.BreakGlass{Active: false},
			},
			DesiredState: []state.DesiredState{
				{
					OSUser: "deploy",
					AuthorizedKeys: []state.AuthorizedKey{
						{
							KeyID:             "key-abc",
							FingerprintSHA256: "SHA256:abcdef",
							PublicKey:          "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deploy-key",
						},
					},
				},
			},
		})
	}))
	defer server.Close()

	logger := telemetry.NewLogger(true)
	client := NewClient(server.URL, "host-1", credential, logger)

	ctx := context.Background()
	resp, err := client.Sync(ctx, &state.SyncRequest{
		HostID: "host-1",
		Status: state.HostStatus{LastApplyResult: "pending", DriftDetected: false},
		Observed: []state.Observed{
			{OSUser: "deploy", ManagedBlockPresent: false, ManagedKeysFingerprints: []string{}},
		},
	})

	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if len(resp.DesiredState) != 1 {
		t.Fatalf("desired_state count = %d, want 1", len(resp.DesiredState))
	}
	if resp.DesiredState[0].OSUser != "deploy" {
		t.Errorf("os_user = %q", resp.DesiredState[0].OSUser)
	}
	if len(resp.DesiredState[0].AuthorizedKeys) != 1 {
		t.Fatalf("authorized_keys count = %d, want 1", len(resp.DesiredState[0].AuthorizedKeys))
	}
	if resp.DesiredState[0].AuthorizedKeys[0].KeyID != "key-abc" {
		t.Errorf("key_id = %q", resp.DesiredState[0].AuthorizedKeys[0].KeyID)
	}
}

// TestE2E_SyncAndApply tests the full daemon sync-and-apply cycle with a mock server.
func TestE2E_SyncAndApply(t *testing.T) {
	credential := "e2e-test-credential"

	// Generate a real SSH key to use as the managed key in server responses.
	// This key will survive validateAndNormalizePublicKey in authorizedkeys.Apply.
	managedKey := generateTestPublicKey(t, "managed@lockwave")

	// Track which sync call we're on
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)

		switch callCount {
		case 1:
			// First sync: return one key
			_ = json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:00:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: false}},
				DesiredState: []state.DesiredState{{
					OSUser: "deploy",
					AuthorizedKeys: []state.AuthorizedKey{
						{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: managedKey},
					},
				}},
			})
		case 2:
			// Second sync: break-glass active, empty desired state
			_ = json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:01:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: true, Scope: strPtr("team")}},
				DesiredState: []state.DesiredState{{
					OSUser:         "deploy",
					AuthorizedKeys: []state.AuthorizedKey{},
				}},
			})
		case 3:
			// Third sync: break-glass deactivated, key returns
			_ = json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:02:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: false}},
				DesiredState: []state.DesiredState{{
					OSUser: "deploy",
					AuthorizedKeys: []state.AuthorizedKey{
						{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: managedKey},
					},
				}},
			})
		}
	}))
	defer server.Close()

	// Set up temp authorized_keys with an existing unmanaged key.
	// Write it directly via os.WriteFile so validation doesn't apply to the
	// pre-existing personal key (it may be a placeholder in a real file).
	unmanagedKey := generateTestPublicKey(t, "personal@laptop")
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	akPath := filepath.Join(sshDir, "authorized_keys")
	if err := os.WriteFile(akPath, []byte(unmanagedKey+"\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	logger := telemetry.NewLogger(true)
	client := NewClient(server.URL, "host-e2e", credential, logger)
	ctx := context.Background()

	cfg := &config.Config{
		APIURL:     server.URL,
		HostID:     "host-e2e",
		Credential: credential,
		PollSecs:   60,
		Users:      []config.ManagedUser{{OSUser: "deploy", AuthorizedKeysPath: akPath}},
	}

	// ── Sync 1: key assigned → should appear in authorized_keys ──
	resp1, err := client.Sync(ctx, &state.SyncRequest{
		HostID:   "host-e2e",
		Status:   state.HostStatus{LastApplyResult: "pending"},
		Observed: []state.Observed{{OSUser: "deploy", ManagedBlockPresent: false, ManagedKeysFingerprints: []string{}}},
	})
	if err != nil {
		t.Fatalf("sync 1 failed: %v", err)
	}

	for _, ds := range resp1.DesiredState {
		for _, u := range cfg.Users {
			if u.OSUser == ds.OSUser {
				if err := authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys, false); err != nil {
					t.Fatalf("apply 1 failed: %v", err)
				}
			}
		}
	}

	content1, _ := os.ReadFile(akPath)
	s1 := string(content1)
	// Unmanaged key must survive (identified by its unique comment).
	if !strings.Contains(s1, "personal@laptop") {
		t.Error("sync 1: unmanaged key was lost")
	}
	// Managed key is identified by its lockwave annotation; the comment field
	// is stripped during normalization by ssh.MarshalAuthorizedKey.
	if !strings.Contains(s1, "# lockwave:k1") {
		t.Error("sync 1: managed key not written")
	}
	if !strings.Contains(s1, authorizedkeys.DefaultBeginMarker) {
		t.Error("sync 1: missing begin marker")
	}

	// ── Sync 2: break-glass → managed block should be empty ──
	resp2, err := client.Sync(ctx, &state.SyncRequest{
		HostID:   "host-e2e",
		Status:   state.HostStatus{LastApplyResult: "success"},
		Observed: []state.Observed{{OSUser: "deploy", ManagedBlockPresent: true, ManagedKeysFingerprints: []string{}}},
	})
	if err != nil {
		t.Fatalf("sync 2 failed: %v", err)
	}

	if !resp2.HostPolicy.BreakGlass.Active {
		t.Error("sync 2: break_glass should be active")
	}

	for _, ds := range resp2.DesiredState {
		for _, u := range cfg.Users {
			if u.OSUser == ds.OSUser {
				if err := authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys, false); err != nil {
					t.Fatalf("apply 2 failed: %v", err)
				}
			}
		}
	}

	content2, _ := os.ReadFile(akPath)
	s2 := string(content2)
	if !strings.Contains(s2, "personal@laptop") {
		t.Error("sync 2: unmanaged key was lost during break-glass")
	}
	// The managed key annotation must be absent during break-glass.
	if strings.Contains(s2, "# lockwave:k1") {
		t.Error("sync 2: managed key should be removed during break-glass")
	}
	if !strings.Contains(s2, authorizedkeys.DefaultBeginMarker) {
		t.Error("sync 2: managed block markers should remain even when empty")
	}

	// ── Sync 3: break-glass deactivated → key returns ──
	resp3, err := client.Sync(ctx, &state.SyncRequest{
		HostID:   "host-e2e",
		Status:   state.HostStatus{LastApplyResult: "success"},
		Observed: []state.Observed{{OSUser: "deploy", ManagedBlockPresent: true, ManagedKeysFingerprints: []string{}}},
	})
	if err != nil {
		t.Fatalf("sync 3 failed: %v", err)
	}

	for _, ds := range resp3.DesiredState {
		for _, u := range cfg.Users {
			if u.OSUser == ds.OSUser {
				if err := authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys, false); err != nil {
					t.Fatalf("apply 3 failed: %v", err)
				}
			}
		}
	}

	content3, _ := os.ReadFile(akPath)
	s3 := string(content3)
	if !strings.Contains(s3, "personal@laptop") {
		t.Error("sync 3: unmanaged key was lost")
	}
	if !strings.Contains(s3, "# lockwave:k1") {
		t.Error("sync 3: managed key should return after break-glass deactivation")
	}
}

func TestHealthCheck_Success(t *testing.T) {
	credential := "health-check-credential"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(state.SyncResponse{
			ServerTime: "2026-02-27T12:00:00Z",
			HostPolicy: state.HostPolicy{
				PollSeconds: 60,
				BreakGlass:  state.BreakGlass{Active: false},
			},
			DesiredState: []state.DesiredState{},
		})
	}))
	defer server.Close()

	logger := telemetry.NewLogger(true)
	client := NewClient(server.URL, "host-health", credential, logger)

	ctx := context.Background()
	resp, err := client.Sync(ctx, &state.SyncRequest{
		HostID:        "host-health",
		DaemonVersion: "1.0.0",
		Status:        state.HostStatus{LastApplyResult: "pending", DriftDetected: false},
		Observed:      []state.Observed{{OSUser: "deploy", ManagedBlockPresent: false, ManagedKeysFingerprints: []string{}}},
	})

	if err != nil {
		t.Fatalf("health check sync failed: %v", err)
	}
	if resp.ServerTime != "2026-02-27T12:00:00Z" {
		t.Errorf("server_time = %q", resp.ServerTime)
	}
	if resp.HostPolicy.PollSeconds != 60 {
		t.Errorf("poll_seconds = %d", resp.HostPolicy.PollSeconds)
	}
}

func TestHealthCheck_ServerDown(t *testing.T) {
	// Use a port that's not listening
	logger := telemetry.NewLogger(true)
	client := NewClient("http://127.0.0.1:1", "host-fail", "cred", logger)

	ctx := context.Background()
	_, err := client.Sync(ctx, &state.SyncRequest{
		HostID:   "host-fail",
		Status:   state.HostStatus{LastApplyResult: "pending"},
		Observed: []state.Observed{},
	})

	if err == nil {
		t.Fatal("expected error when server is unreachable")
	}
}

func strPtr(s string) *string {
	return &s
}
