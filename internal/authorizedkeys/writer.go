package authorizedkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/lockwave-io/daemon/internal/state"
	"github.com/lockwave-io/daemon/internal/system"
)

// validateAndNormalizePublicKey parses a raw SSH public key string using the
// ssh package and re-serializes it via MarshalAuthorizedKey. This strips any
// injected authorized_keys options (e.g. command=, environment=) that could
// allow privilege escalation. Returns an error if the key cannot be parsed.
func validateAndNormalizePublicKey(raw string) (string, error) {
	pubKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(raw))
	if err != nil {
		return "", fmt.Errorf("authorizedkeys: invalid SSH public key: %w", err)
	}
	// MarshalAuthorizedKey appends a trailing newline; trim it so the caller
	// controls line formatting.
	normalized := strings.TrimRight(string(ssh.MarshalAuthorizedKey(pubKey)), "\n")
	return normalized, nil
}

// Apply writes the desired state to the authorized_keys file using atomic write.
// When exclusive is false, it preserves any keys outside the managed block.
// When exclusive is true, only managed keys are written (unmanaged keys are removed).
func Apply(path string, keys []state.AuthorizedKey, exclusive bool) error {
	// Parse existing file to preserve unmanaged keys (when not exclusive)
	parsed, err := Parse(path)
	if err != nil {
		return fmt.Errorf("authorizedkeys: parse existing: %w", err)
	}

	// Build new file content
	var lines []string

	// Pre-block (unmanaged keys before the managed section) — skip in exclusive mode
	if !exclusive {
		lines = append(lines, parsed.PreBlock...)
	}

	// Managed block
	lines = append(lines, DefaultBeginMarker)
	for _, key := range keys {
		normalized, err := validateAndNormalizePublicKey(key.PublicKey)
		if err != nil {
			return fmt.Errorf("authorizedkeys: key %s: %w", key.KeyID, err)
		}
		// Format: <public_key> # lockwave:<key_id>
		line := fmt.Sprintf("%s # lockwave:%s", normalized, key.KeyID)
		lines = append(lines, line)
	}
	lines = append(lines, DefaultEndMarker)

	// Post-block (unmanaged keys after the managed section) — skip in exclusive mode
	if !exclusive {
		lines = append(lines, parsed.PostBlock...)
	}

	content := strings.Join(lines, "\n") + "\n"

	// Ensure the directory exists
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("authorizedkeys: mkdir %s: %w", dir, err)
	}

	// Atomic write: temp file → fsync → rename
	if err := system.AtomicWrite(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("authorizedkeys: atomic write: %w", err)
	}

	return nil
}

// HashManagedBlock reads the authorized_keys file at path and returns a SHA-256
// hex digest of the managed block content (markers + key lines). Returns empty
// string if the file doesn't exist or has no managed block.
func HashManagedBlock(path string) (string, error) {
	parsed, err := Parse(path)
	if err != nil {
		return "", err
	}
	if !parsed.HasManagedBlock {
		return "", nil
	}

	// Reconstruct the managed block exactly as written
	var lines []string
	lines = append(lines, DefaultBeginMarker)
	lines = append(lines, parsed.ManagedKeys...)
	lines = append(lines, DefaultEndMarker)
	content := strings.Join(lines, "\n")

	h := sha256.Sum256([]byte(content))
	return hex.EncodeToString(h[:]), nil
}

// StripManagedBlock removes the entire managed block (markers and keys) from
// the authorized_keys file, leaving only unmanaged keys intact. This is used
// when a user is removed from management — we don't want to leave stale markers.
func StripManagedBlock(path string) error {
	parsed, err := Parse(path)
	if err != nil {
		return fmt.Errorf("authorizedkeys: parse for strip: %w", err)
	}
	if !parsed.HasManagedBlock {
		return nil
	}

	var lines []string
	lines = append(lines, parsed.PreBlock...)
	lines = append(lines, parsed.PostBlock...)

	content := strings.Join(lines, "\n")
	if content != "" {
		content += "\n"
	}

	if err := system.AtomicWrite(path, []byte(content), 0o600); err != nil {
		return fmt.Errorf("authorizedkeys: atomic write (strip): %w", err)
	}

	return nil
}

// RenderManagedBlock produces just the managed block content (for testing/display).
// Keys that fail validation are skipped rather than written.
func RenderManagedBlock(keys []state.AuthorizedKey) string {
	var lines []string
	lines = append(lines, DefaultBeginMarker)
	for _, key := range keys {
		normalized, err := validateAndNormalizePublicKey(key.PublicKey)
		if err != nil {
			continue
		}
		line := fmt.Sprintf("%s # lockwave:%s", normalized, key.KeyID)
		lines = append(lines, line)
	}
	lines = append(lines, DefaultEndMarker)
	return strings.Join(lines, "\n")
}
