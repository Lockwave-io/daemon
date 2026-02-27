package authorizedkeys

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/lockwave-io/daemon/internal/state"
	"github.com/lockwave-io/daemon/internal/system"
)

// Apply writes the desired state to the authorized_keys file using atomic write.
// It preserves any keys outside the managed block.
func Apply(path string, keys []state.AuthorizedKey) error {
	// Parse existing file to preserve unmanaged keys
	parsed, err := Parse(path)
	if err != nil {
		return fmt.Errorf("authorizedkeys: parse existing: %w", err)
	}

	// Build new file content
	var lines []string

	// Pre-block (unmanaged keys before the managed section)
	lines = append(lines, parsed.PreBlock...)

	// Managed block
	lines = append(lines, DefaultBeginMarker)
	for _, key := range keys {
		// Format: <public_key> # lockwave:<key_id>
		line := fmt.Sprintf("%s # lockwave:%s", key.PublicKey, key.KeyID)
		lines = append(lines, line)
	}
	lines = append(lines, DefaultEndMarker)

	// Post-block (unmanaged keys after the managed section)
	lines = append(lines, parsed.PostBlock...)

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

// RenderManagedBlock produces just the managed block content (for testing/display).
func RenderManagedBlock(keys []state.AuthorizedKey) string {
	var lines []string
	lines = append(lines, DefaultBeginMarker)
	for _, key := range keys {
		line := fmt.Sprintf("%s # lockwave:%s", key.PublicKey, key.KeyID)
		lines = append(lines, line)
	}
	lines = append(lines, DefaultEndMarker)
	return strings.Join(lines, "\n")
}
