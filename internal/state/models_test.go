package state

import (
	"encoding/json"
	"testing"
)

func TestSyncRequest_MarshalUnmarshal(t *testing.T) {
	req := SyncRequest{
		HostID: "host-123",
		Status: HostStatus{
			LastApplyResult: "success",
			DriftDetected:   false,
			AppliedAt:       strPtr("2025-01-15T12:00:00Z"),
		},
		Observed: []Observed{
			{
				OSUser:                  "root",
				ManagedBlockPresent:     true,
				ManagedKeysFingerprints: []string{"SHA256:abc"},
			},
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded SyncRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.HostID != req.HostID || decoded.Status.LastApplyResult != req.Status.LastApplyResult {
		t.Errorf("round-trip mismatch: got %+v", decoded)
	}
}

func TestDesiredState_MarshalUnmarshal(t *testing.T) {
	ds := DesiredState{
		OSUser: "ubuntu",
		AuthorizedKeys: []AuthorizedKey{
			{KeyID: "k1", FingerprintSHA256: "SHA256:xyz", PublicKey: "ssh-ed25519 AAAA..."},
		},
	}
	data, err := json.Marshal(ds)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded DesiredState
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded.OSUser != ds.OSUser || len(decoded.AuthorizedKeys) != 1 {
		t.Errorf("round-trip mismatch: got %+v", decoded)
	}
}

func TestRegisterRequest_DiscoveredKeys_MarshalUnmarshal(t *testing.T) {
	req := RegisterRequest{
		EnrollmentToken: "tok123",
		Host: HostInfo{
			Hostname:      "web-01",
			OS:            "linux",
			Arch:          "amd64",
			DaemonVersion: "1.0.0",
			IP:            "10.0.0.1",
		},
		ManagedUsers: []UserEntry{{OSUser: "deploy"}},
		DiscoveredKeys: []DiscoveredKey{
			{OSUser: "deploy", PublicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAITest deploy@host"},
			{OSUser: "root", PublicKey: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ root@host"},
		},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded RegisterRequest
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if len(decoded.DiscoveredKeys) != 2 {
		t.Fatalf("expected 2 discovered keys, got %d", len(decoded.DiscoveredKeys))
	}
	if decoded.DiscoveredKeys[0].OSUser != "deploy" {
		t.Errorf("expected os_user=deploy, got %s", decoded.DiscoveredKeys[0].OSUser)
	}
	if decoded.DiscoveredKeys[1].PublicKey != "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQ root@host" {
		t.Errorf("public_key mismatch: %s", decoded.DiscoveredKeys[1].PublicKey)
	}
}

func TestRegisterRequest_OmitsEmptyDiscoveredKeys(t *testing.T) {
	req := RegisterRequest{
		EnrollmentToken: "tok123",
		Host:            HostInfo{Hostname: "web-01"},
		ManagedUsers:    []UserEntry{{OSUser: "deploy"}},
	}
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// The JSON should not contain "discovered_keys" when the slice is nil
	var m map[string]interface{}
	if err := json.Unmarshal(data, &m); err != nil {
		t.Fatalf("unmarshal to map: %v", err)
	}
	if _, exists := m["discovered_keys"]; exists {
		t.Error("expected discovered_keys to be omitted from JSON when nil")
	}
}

func strPtr(s string) *string {
	return &s
}
