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

func strPtr(s string) *string {
	return &s
}
