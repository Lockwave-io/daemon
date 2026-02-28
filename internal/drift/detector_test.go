package drift

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/lockwave-io/daemon/internal/authorizedkeys"
	"github.com/lockwave-io/daemon/internal/state"
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

func writeAuthorizedKeys(t *testing.T, path string, keys []state.AuthorizedKey) {
	t.Helper()
	if err := authorizedkeys.Apply(path, keys, false); err != nil {
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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "test@host")},
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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "test@host")},
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
	if err := os.WriteFile(path, []byte(modified), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "test@host")},
	}
	writeAuthorizedKeys(t, path, keys)

	if err := d.RecordApplied("deploy", path); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Delete the file — managed block is gone
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "deploy@host")},
	}
	keysB := []state.AuthorizedKey{
		{KeyID: "k2", FingerprintSHA256: "SHA256:def", PublicKey: generateTestPublicKey(t, "www@host")},
	}

	writeAuthorizedKeys(t, pathA, keysA)
	writeAuthorizedKeys(t, pathB, keysB)

	if err := d.RecordApplied("deploy", pathA); err != nil {
		t.Fatalf("record deploy: %v", err)
	}
	if err := d.RecordApplied("www", pathB); err != nil {
		t.Fatalf("record www: %v", err)
	}

	// No drift for either
	dA, _ := d.Check("deploy", pathA)
	dB, _ := d.Check("www", pathB)
	if dA || dB {
		t.Error("expected no drift for either user")
	}

	// Edit only deploy's file
	if err := os.Remove(pathA); err != nil {
		t.Fatalf("remove: %v", err)
	}
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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "test@host")},
	}
	writeAuthorizedKeys(t, path, keys)
	if err := d.RecordApplied("deploy", path); err != nil {
		t.Fatalf("record: %v", err)
	}

	// Delete file to create drift
	if err := os.Remove(path); err != nil {
		t.Fatalf("remove: %v", err)
	}

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
	if err := os.WriteFile(path, []byte("ssh-rsa AAAAB3 user@laptop\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

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
		{KeyID: "k1", FingerprintSHA256: "SHA256:abc", PublicKey: generateTestPublicKey(t, "test@host")},
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
