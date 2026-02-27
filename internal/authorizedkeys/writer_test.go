package authorizedkeys

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lockwave-io/daemon/internal/state"
)

func TestApply_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ssh", "authorized_keys")

	keys := []state.AuthorizedKey{
		{KeyID: "key-1", FingerprintSHA256: "SHA256:abc", PublicKey: "ssh-ed25519 AAAAC3Nza... key1"},
	}

	if err := Apply(path, keys); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}

	s := string(content)
	if !strings.Contains(s, DefaultBeginMarker) {
		t.Error("missing begin marker")
	}
	if !strings.Contains(s, DefaultEndMarker) {
		t.Error("missing end marker")
	}
	if !strings.Contains(s, "ssh-ed25519 AAAAC3Nza... key1 # lockwave:key-1") {
		t.Error("missing managed key line")
	}
}

func TestApply_PreservesUnmanagedKeys(t *testing.T) {
	existing := "ssh-ed25519 AAAAC3Nza... personal-key\n"
	path := writeTempFile(t, existing)

	keys := []state.AuthorizedKey{
		{KeyID: "key-1", PublicKey: "ssh-rsa AAAAB3Nza... managed"},
	}

	if err := Apply(path, keys); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	s := string(content)

	// Unmanaged key should still be present
	if !strings.Contains(s, "ssh-ed25519 AAAAC3Nza... personal-key") {
		t.Error("unmanaged key was not preserved")
	}
	// Managed key should be present
	if !strings.Contains(s, "ssh-rsa AAAAB3Nza... managed # lockwave:key-1") {
		t.Error("managed key was not written")
	}
}

func TestApply_ReplacesExistingManagedBlock(t *testing.T) {
	existing := `ssh-ed25519 AAAAC3Nza... personal
# --- BEGIN LOCKWAVE MANAGED BLOCK ---
ssh-rsa AAAAB3Nza... old-managed
# --- END LOCKWAVE MANAGED BLOCK ---
ssh-rsa AAAAB3Nza... other-personal
`
	path := writeTempFile(t, existing)

	keys := []state.AuthorizedKey{
		{KeyID: "new-1", PublicKey: "ssh-ed25519 AAAAC3new... new-managed"},
	}

	if err := Apply(path, keys); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	s := string(content)

	// Old managed key should be gone
	if strings.Contains(s, "old-managed") {
		t.Error("old managed key should have been replaced")
	}
	// New managed key should be present
	if !strings.Contains(s, "ssh-ed25519 AAAAC3new... new-managed # lockwave:new-1") {
		t.Error("new managed key was not written")
	}
	// Both unmanaged keys should be preserved
	if !strings.Contains(s, "ssh-ed25519 AAAAC3Nza... personal") {
		t.Error("pre-block unmanaged key not preserved")
	}
	if !strings.Contains(s, "ssh-rsa AAAAB3Nza... other-personal") {
		t.Error("post-block unmanaged key not preserved")
	}
}

func TestApply_EmptyKeysCreatesEmptyManagedBlock(t *testing.T) {
	path := writeTempFile(t, "ssh-ed25519 existing\n")

	if err := Apply(path, nil); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	s := string(content)

	if !strings.Contains(s, DefaultBeginMarker) {
		t.Error("missing begin marker even with empty keys")
	}
	if !strings.Contains(s, DefaultEndMarker) {
		t.Error("missing end marker even with empty keys")
	}
	// Existing key should be preserved
	if !strings.Contains(s, "ssh-ed25519 existing") {
		t.Error("existing key not preserved")
	}
}

func TestApply_FilePermissions(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	if err := Apply(path, nil); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestRenderManagedBlock(t *testing.T) {
	keys := []state.AuthorizedKey{
		{KeyID: "k1", PublicKey: "ssh-ed25519 AAA... key1"},
		{KeyID: "k2", PublicKey: "ssh-rsa BBB... key2"},
	}

	block := RenderManagedBlock(keys)

	if !strings.HasPrefix(block, DefaultBeginMarker) {
		t.Error("block should start with begin marker")
	}
	if !strings.HasSuffix(block, DefaultEndMarker) {
		t.Error("block should end with end marker")
	}
	if !strings.Contains(block, "# lockwave:k1") {
		t.Error("block should contain key ID annotation")
	}
}
