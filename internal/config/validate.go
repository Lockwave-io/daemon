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
// The path is cleaned with filepath.Clean before all checks so that redundant
// separators, dot-segments, and similar lexical anomalies are normalised.
func ValidateAuthorizedKeysPath(path string) error {
	if path == "" {
		return nil // empty means use default; resolved elsewhere
	}

	// Lexically normalise the path before any check so that constructs such as
	// "/home/user/./foo/../.ssh/authorized_keys" are reduced to their canonical
	// form and cannot bypass prefix or traversal checks.
	path = filepath.Clean(path)

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
	if !isUnderAllowedPrefix(path) {
		return fmt.Errorf("authorized_keys_path is outside allowed directories (%v): %s", AllowedPathPrefixes, path)
	}

	return nil
}

// ValidateAuthorizedKeysPathRuntime performs both the lexical validation from
// ValidateAuthorizedKeysPath and a runtime symlink-resolution check. It resolves
// the parent directory of path to its real on-disk location via
// filepath.EvalSymlinks and re-validates the resolved path against the allowed
// directory prefixes. This prevents an attacker from using a symlinked directory
// to redirect an ostensibly safe path to a location outside the allowed set.
//
// Because the target file does not need to exist yet, only the directory
// component is evaluated; a missing file in an existing directory is acceptable.
func ValidateAuthorizedKeysPathRuntime(path string) error {
	// Lexical validation first — fast and works without filesystem access.
	if err := ValidateAuthorizedKeysPath(path); err != nil {
		return err
	}

	if path == "" {
		return nil
	}

	// filepath.Clean is already applied inside ValidateAuthorizedKeysPath, but
	// apply it here as well so the dir computation below is based on the same
	// normalised value regardless of call order.
	cleanPath := filepath.Clean(path)
	dir := filepath.Dir(cleanPath)

	// Resolve symlinks in the directory component only. The file itself may not
	// yet exist (it will be created on first sync), so we only evaluate its
	// parent directory.
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return fmt.Errorf("authorized_keys_path: cannot resolve directory %q: %w", dir, err)
	}

	// Reconstruct the full path using the resolved directory and the original
	// filename, then re-validate against allowed prefixes.
	resolvedPath := filepath.Join(resolvedDir, filepath.Base(cleanPath))
	if !isUnderAllowedPrefix(resolvedPath) {
		return fmt.Errorf(
			"authorized_keys_path resolves outside allowed directories (%v): %s -> %s",
			AllowedPathPrefixes, path, resolvedPath,
		)
	}

	return nil
}

// isUnderAllowedPrefix reports whether path starts with one of AllowedPathPrefixes.
func isUnderAllowedPrefix(path string) bool {
	for _, prefix := range AllowedPathPrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
