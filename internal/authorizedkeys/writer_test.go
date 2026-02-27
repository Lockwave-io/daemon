package authorizedkeys

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

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
	// MarshalAuthorizedKey produces "<type> <base64>\n"; strip the newline so
	// we can add a comment like a real key line.
	line := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pub)), "\n")
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestApply_CreatesNewFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, ".ssh", "authorized_keys")

	rawKey := generateTestPublicKey(t, "key1")
	keys := []state.AuthorizedKey{
		{KeyID: "key-1", FingerprintSHA256: "SHA256:abc", PublicKey: rawKey},
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
	if !strings.Contains(s, "# lockwave:key-1") {
		t.Error("missing managed key line")
	}
}

func TestApply_PreservesUnmanagedKeys(t *testing.T) {
	// Write an unmanaged key line directly — bypasses Apply validation intentionally.
	unmanagedKey := generateTestPublicKey(t, "personal-key")
	existing := unmanagedKey + "\n"
	path := writeTempFile(t, existing)

	managedKey := generateTestPublicKey(t, "managed")
	keys := []state.AuthorizedKey{
		{KeyID: "key-1", PublicKey: managedKey},
	}

	if err := Apply(path, keys); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	s := string(content)

	// Unmanaged key should still be present (by comment, which survives normalization).
	if !strings.Contains(s, "personal-key") {
		t.Error("unmanaged key was not preserved")
	}
	// Managed key annotation should be present.
	if !strings.Contains(s, "# lockwave:key-1") {
		t.Error("managed key was not written")
	}
}

func TestApply_ReplacesExistingManagedBlock(t *testing.T) {
	// Construct the existing file manually — raw strings bypass Apply validation.
	personalKey := generateTestPublicKey(t, "personal")
	otherPersonalKey := generateTestPublicKey(t, "other-personal")
	existing := personalKey + "\n" +
		"# --- BEGIN LOCKWAVE MANAGED BLOCK ---\n" +
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIoldkey old-managed\n" +
		"# --- END LOCKWAVE MANAGED BLOCK ---\n" +
		otherPersonalKey + "\n"
	path := writeTempFile(t, existing)

	newKey := generateTestPublicKey(t, "new-managed")
	keys := []state.AuthorizedKey{
		{KeyID: "new-1", PublicKey: newKey},
	}

	if err := Apply(path, keys); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}

	content, _ := os.ReadFile(path)
	s := string(content)

	// Old managed key should be gone (identified by its unique comment).
	if strings.Contains(s, "old-managed") {
		t.Error("old managed key should have been replaced")
	}
	// New managed key annotation should be present.
	if !strings.Contains(s, "# lockwave:new-1") {
		t.Error("new managed key was not written")
	}
	// Both unmanaged keys should be preserved (identified by their comments).
	if !strings.Contains(s, "personal") {
		t.Error("pre-block unmanaged key not preserved")
	}
	if !strings.Contains(s, "other-personal") {
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
		{KeyID: "k1", PublicKey: generateTestPublicKey(t, "key1")},
		{KeyID: "k2", PublicKey: generateTestPublicKey(t, "key2")},
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

// ---------------------------------------------------------------------------
// SSH public-key validation tests
// ---------------------------------------------------------------------------

// TestValidateAndNormalizePublicKey_ValidKey verifies that a well-formed key
// passes validation and comes back in canonical form (no trailing newline).
func TestValidateAndNormalizePublicKey_ValidKey(t *testing.T) {
	raw := generateTestPublicKey(t, "user@host")

	got, err := validateAndNormalizePublicKey(raw)
	if err != nil {
		t.Fatalf("unexpected error for valid key: %v", err)
	}
	if strings.HasSuffix(got, "\n") {
		t.Error("normalized key should not have a trailing newline")
	}
	// The normalized key must still be parseable.
	if _, _, _, _, err := ssh.ParseAuthorizedKey([]byte(got)); err != nil {
		t.Errorf("re-parse of normalized key failed: %v", err)
	}
}

// TestValidateAndNormalizePublicKey_InjectedOptionsStripped verifies that an
// authorized_keys line carrying injected options (e.g. command=, no-pty) is
// accepted as a valid key but has its options stripped in the output.
func TestValidateAndNormalizePublicKey_InjectedOptionsStripped(t *testing.T) {
	// Build a bare key first, then prepend a dangerous option.
	bareKey := generateTestPublicKey(t, "victim@host")
	withOptions := `command="/bin/evil",no-pty ` + bareKey

	got, err := validateAndNormalizePublicKey(withOptions)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if strings.Contains(got, "command=") {
		t.Error("injected command= option was not stripped from normalized key")
	}
	if strings.Contains(got, "no-pty") {
		t.Error("injected no-pty option was not stripped from normalized key")
	}
}

// TestValidateAndNormalizePublicKey_MalformedKeyRejected verifies that a
// completely invalid key string is rejected with a non-nil error.
func TestValidateAndNormalizePublicKey_MalformedKeyRejected(t *testing.T) {
	cases := []struct {
		name string
		raw  string
	}{
		{"empty", ""},
		{"random garbage", "not-a-key at all !!!"},
		{"comment only", "# this is a comment"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := validateAndNormalizePublicKey(tc.raw)
			if err == nil {
				t.Errorf("expected error for malformed key %q, got nil", tc.raw)
			}
		})
	}
}

// TestApply_RejectsInjectedOptionsInKey verifies that Apply returns an error
// when a key with injected authorized_keys options is provided, preventing the
// raw dangerous string from ever reaching the file.
func TestApply_RejectsInjectedOptionsInKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")

	bareKey := generateTestPublicKey(t, "victim@host")
	keys := []state.AuthorizedKey{
		{KeyID: "evil-1", PublicKey: `command="/bin/evil",no-pty ` + bareKey},
	}

	// Apply must NOT propagate the raw injected options into the file.
	// Either it returns an error (strict) or it strips the options.
	// Our implementation strips options via re-serialization, so we verify
	// the file content never contains the injected directive.
	if err := Apply(path, keys); err != nil {
		// If the implementation chooses to reject, that is also acceptable.
		return
	}

	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if strings.Contains(string(content), "command=") {
		t.Error("injected command= option must not appear in the written authorized_keys file")
	}
}
