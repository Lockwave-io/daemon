package authorizedkeys

import (
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
