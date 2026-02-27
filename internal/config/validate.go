package config

import (
	"fmt"
	"path/filepath"
	"strings"
)

// AllowedPathPrefixes defines the directories where authorized_keys files may reside.
var AllowedPathPrefixes = []string{
	"/home/",
	"/root/",
	"/var/",
	"/Users/",
}

// ValidateAuthorizedKeysPath checks that a path is safe for use as an authorized_keys target.
// It rejects relative paths, path traversal, and paths outside allowed directories.
func ValidateAuthorizedKeysPath(path string) error {
	if path == "" {
		return nil // empty means use default; resolved elsewhere
	}

	if !filepath.IsAbs(path) {
		return fmt.Errorf("authorized_keys_path must be absolute, got: %s", path)
	}

	if strings.Contains(path, "..") {
		return fmt.Errorf("authorized_keys_path must not contain '..': %s", path)
	}

	// Must end with "authorized_keys" or be inside a ".ssh" directory
	base := filepath.Base(path)
	dir := filepath.Dir(path)
	if base != "authorized_keys" && !strings.Contains(dir, "/.ssh") {
		return fmt.Errorf("authorized_keys_path must end with 'authorized_keys' or be inside a .ssh directory: %s", path)
	}

	// Must be under an allowed prefix
	allowed := false
	for _, prefix := range AllowedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("authorized_keys_path is outside allowed directories (%v): %s", AllowedPathPrefixes, path)
	}

	return nil
}
