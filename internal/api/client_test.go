package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lockwave-io/daemon/internal/authorizedkeys"
	"github.com/lockwave-io/daemon/internal/config"
	"github.com/lockwave-io/daemon/internal/state"
	"github.com/lockwave-io/daemon/internal/telemetry"
)

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
		json.NewEncoder(w).Encode(state.RegisterResponse{
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

	logger := telemetry.NewLogger(slog.LevelDebug)
	ctx := context.Background()

	resp, err := Register(ctx, server.URL, "test-token-value", state.HostInfo{
		Hostname:      "test-host",
		OS:            "linux",
		Arch:          "x86_64",
		DaemonVersion: "1.0.0",
		IP:            "10.0.0.1",
	}, []state.UserEntry{{OSUser: "deploy"}}, logger)

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

func TestRegister_InvalidToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"error":"Invalid token"}`))
	}))
	defer server.Close()

	logger := telemetry.NewLogger(slog.LevelDebug)
	ctx := context.Background()

	_, err := Register(ctx, server.URL, "bad-token", state.HostInfo{
		Hostname: "h", OS: "linux", Arch: "x86_64", DaemonVersion: "1.0.0", IP: "1.2.3.4",
	}, []state.UserEntry{{OSUser: "u"}}, logger)

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
		json.NewEncoder(w).Encode(state.SyncResponse{
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

	logger := telemetry.NewLogger(slog.LevelDebug)
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

	// Track which sync call we're on
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusOK)

		switch callCount {
		case 1:
			// First sync: return one key
			json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:00:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: false}},
				DesiredState: []state.DesiredState{{
					OSUser: "deploy",
					AuthorizedKeys: []state.AuthorizedKey{
						{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 managed@lockwave"},
					},
				}},
			})
		case 2:
			// Second sync: break-glass active, empty desired state
			json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:01:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: true, Scope: strPtr("team")}},
				DesiredState: []state.DesiredState{{
					OSUser:         "deploy",
					AuthorizedKeys: []state.AuthorizedKey{},
				}},
			})
		case 3:
			// Third sync: break-glass deactivated, key returns
			json.NewEncoder(w).Encode(state.SyncResponse{
				ServerTime: "2026-02-26T12:02:00Z",
				HostPolicy: state.HostPolicy{PollSeconds: 60, BreakGlass: state.BreakGlass{Active: false}},
				DesiredState: []state.DesiredState{{
					OSUser: "deploy",
					AuthorizedKeys: []state.AuthorizedKey{
						{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 managed@lockwave"},
					},
				}},
			})
		}
	}))
	defer server.Close()

	// Set up temp authorized_keys with an existing unmanaged key
	dir := t.TempDir()
	sshDir := filepath.Join(dir, ".ssh")
	os.MkdirAll(sshDir, 0o700)
	akPath := filepath.Join(sshDir, "authorized_keys")
	os.WriteFile(akPath, []byte("ssh-rsa AAAAB3existing... personal@laptop\n"), 0o600)

	logger := telemetry.NewLogger(slog.LevelDebug)
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

	// Apply desired state
	for _, ds := range resp1.DesiredState {
		for _, u := range cfg.Users {
			if u.OSUser == ds.OSUser {
				if err := authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys); err != nil {
					t.Fatalf("apply 1 failed: %v", err)
				}
			}
		}
	}

	// Verify file
	content1, _ := os.ReadFile(akPath)
	s1 := string(content1)
	if !strings.Contains(s1, "ssh-rsa AAAAB3existing... personal@laptop") {
		t.Error("sync 1: unmanaged key was lost")
	}
	if !strings.Contains(s1, "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1 managed@lockwave # lockwave:k1") {
		t.Error("sync 1: managed key not written")
	}
	if !strings.Contains(s1, authorizedkeys.DefaultBeginMarker) {
		t.Error("sync 1: missing begin marker")
	}

	// ── Sync 2: break-glass → managed block should be empty ──
	resp2, err := client.Sync(ctx, &state.SyncRequest{
		HostID:   "host-e2e",
		Status:   state.HostStatus{LastApplyResult: "success"},
		Observed: []state.Observed{{OSUser: "deploy", ManagedBlockPresent: true, ManagedKeysFingerprints: []string{"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKey1"}}},
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
				authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys)
			}
		}
	}

	content2, _ := os.ReadFile(akPath)
	s2 := string(content2)
	if !strings.Contains(s2, "ssh-rsa AAAAB3existing... personal@laptop") {
		t.Error("sync 2: unmanaged key was lost during break-glass")
	}
	if strings.Contains(s2, "managed@lockwave") {
		t.Error("sync 2: managed key should be removed during break-glass")
	}
	// Managed block markers should still exist (empty block)
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
				authorizedkeys.Apply(u.ResolveAuthorizedKeysPath(), ds.AuthorizedKeys)
			}
		}
	}

	content3, _ := os.ReadFile(akPath)
	s3 := string(content3)
	if !strings.Contains(s3, "ssh-rsa AAAAB3existing... personal@laptop") {
		t.Error("sync 3: unmanaged key was lost")
	}
	if !strings.Contains(s3, "managed@lockwave # lockwave:k1") {
		t.Error("sync 3: managed key should return after break-glass deactivation")
	}
}

func strPtr(s string) *string {
	return &s
}
