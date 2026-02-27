package drift

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lockwave-io/daemon/internal/authorizedkeys"
	"github.com/lockwave-io/daemon/internal/state"
)

func writeAuthorizedKeys(t *testing.T, path string, keys []state.AuthorizedKey) {
	t.Helper()
	if err := authorizedkeys.Apply(path, keys); err != nil {
		t.Fatalf("apply keys: %v", err)
	}
}

func TestDetector_NoDriftOnFirstRun(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	drifted, err := d.Check("deploy", path)
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if drifted {
		t.Error("expected no drift on first run (no baseline)")
	}
}

func TestDetector_NoDriftAfterApply(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 test@host"},
	}
	writeAuthorizedKeys(t, path, keys)

	if err := d.RecordApplied("deploy", path); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Check immediately after apply — no drift
	drifted, err := d.Check("deploy", path)
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if drifted {
		t.Error("expected no drift immediately after apply")
	}
}

func TestDetector_DriftAfterExternalEdit(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 test@host"},
	}
	writeAuthorizedKeys(t, path, keys)

	if err := d.RecordApplied("deploy", path); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Simulate external edit: replace the managed block content with different keys
	content, _ := os.ReadFile(path)
	modified := strings.Replace(
		string(content),
		authorizedkeys.DefaultEndMarker,
		"ssh-rsa AAAAB3rogue rogue@attacker\n"+authorizedkeys.DefaultEndMarker,
		1,
	)
	os.WriteFile(path, []byte(modified), 0o600)

	drifted, err := d.Check("deploy", path)
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !drifted {
		t.Error("expected drift after external edit")
	}
}

func TestDetector_DriftAfterFileDeleted(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 test@host"},
	}
	writeAuthorizedKeys(t, path, keys)

	if err := d.RecordApplied("deploy", path); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Delete the file — managed block is gone
	os.Remove(path)

	drifted, err := d.Check("deploy", path)
	if err != nil {
		t.Fatalf("check error: %v", err)
	}
	if !drifted {
		t.Error("expected drift after file deletion")
	}
}

func TestDetector_MultipleUsers(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()

	pathA := filepath.Join(dir, "ak_deploy")
	pathB := filepath.Join(dir, "ak_www")

	keysA := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 deploy@host"},
	}
	keysB := []state.AuthorizedKey{
		{KeyID: "k2", FingerprintSHA256: "SHA256:def", PublicKey: "ssh-ed25519 AAAAC4 www@host"},
	}

	writeAuthorizedKeys(t, pathA, keysA)
	writeAuthorizedKeys(t, pathB, keysB)

	d.RecordApplied("deploy", pathA)
	d.RecordApplied("www", pathB)

	// No drift for either
	dA, _ := d.Check("deploy", pathA)
	dB, _ := d.Check("www", pathB)
	if dA || dB {
		t.Error("expected no drift for either user")
	}

	// Edit only deploy's file
	os.Remove(pathA)
	dA, _ = d.Check("deploy", pathA)
	dB, _ = d.Check("www", pathB)
	if !dA {
		t.Error("expected drift for deploy")
	}
	if dB {
		t.Error("expected no drift for www")
	}
}

func TestDetector_Reset(t *testing.T) {
	d := NewDetector()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 test@host"},
	}
	writeAuthorizedKeys(t, path, keys)
	d.RecordApplied("deploy", path)

	// Delete file to create drift
	os.Remove(path)

	// Reset clears baseline — so no drift reported
	d.Reset()
	drifted, _ := d.Check("deploy", path)
	if drifted {
		t.Error("expected no drift after reset")
	}
}

func TestHashManagedBlock_NoFile(t *testing.T) {
	h, err := authorizedkeys.HashManagedBlock("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Errorf("expected empty hash for missing file, got %q", h)
	}
}

func TestHashManagedBlock_NoManagedBlock(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	os.WriteFile(path, []byte("ssh-rsa AAAAB3 user@laptop\n"), 0o600)

	h, err := authorizedkeys.HashManagedBlock(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if h != "" {
		t.Errorf("expected empty hash for file without managed block, got %q", h)
	}
}

func TestHashManagedBlock_Deterministic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3 test@host"},
	}
	writeAuthorizedKeys(t, path, keys)

	h1, _ := authorizedkeys.HashManagedBlock(path)
	h2, _ := authorizedkeys.HashManagedBlock(path)

	if h1 == "" {
		t.Fatal("hash should not be empty")
	}
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}
