package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestValidateAuthorizedKeysPath(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr bool
		errMsg  string
	}{
		{name: "empty is allowed", path: "", wantErr: false},
		{name: "valid home path", path: "/home/deploy/.ssh/authorized_keys", wantErr: false},
		{name: "valid root path", path: "/root/.ssh/authorized_keys", wantErr: false},
		{name: "valid Users path", path: "/Users/admin/.ssh/authorized_keys", wantErr: false},
		{name: "valid var path", path: "/var/lib/something/.ssh/authorized_keys", wantErr: false},
		{name: "relative path rejected", path: "home/user/.ssh/authorized_keys", wantErr: true, errMsg: "must be absolute"},
		// After filepath.Clean, /home/user/../etc/shadow becomes /home/etc/shadow.
		// The '..' is gone; the cleaned path is rejected because the filename is
		// not 'authorized_keys' and the directory does not contain '/.ssh'.
		{name: "path traversal rejected", path: "/home/user/../etc/shadow", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		{name: "outside allowed dirs", path: "/etc/shadow", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		{name: "wrong filename outside .ssh", path: "/home/user/keys", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		{name: "/tmp rejected", path: "/tmp/authorized_keys", wantErr: true, errMsg: "outside allowed directories"},
		// After filepath.Clean, /home/user/../../etc/passwd becomes /etc/passwd.
		// The filename is not 'authorized_keys' and the dir has no '/.ssh',
		// so the check that fires first is the filename/directory check.
		{name: "absolute but traversal", path: "/home/user/../../etc/passwd", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		// Verify filepath.Clean normalisation: dot and double-dot segments that
		// reduce to a valid path should be accepted after cleaning.
		{
			name:    "dot segments cleaned to valid path",
			path:    "/home/user/./foo/../.ssh/authorized_keys",
			wantErr: false,
		},
		// A path that cleans to something outside allowed directories must be
		// rejected even if the raw string has an allowed prefix.
		{
			name:    "dot segments cleaned to outside allowed dirs",
			path:    "/home/user/../../tmp/authorized_keys",
			wantErr: true,
			errMsg:  "outside allowed directories",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateAuthorizedKeysPath(tt.path)
			if tt.wantErr && err == nil {
				t.Errorf("expected error containing %q, got nil", tt.errMsg)
			}
			if !tt.wantErr && err != nil {
				t.Errorf("expected no error, got: %v", err)
			}
			if tt.wantErr && err != nil && tt.errMsg != "" {
				if got := err.Error(); !containsStr(got, tt.errMsg) {
					t.Errorf("expected error containing %q, got: %s", tt.errMsg, got)
				}
			}
		})
	}
}

// TestValidateAuthorizedKeysPath_CleanNormalization verifies that filepath.Clean
// is applied to the input before any prefix or traversal check, so lexically
// equivalent paths are treated identically regardless of redundant segments.
func TestValidateAuthorizedKeysPath_CleanNormalization(t *testing.T) {
	// These two paths are lexically different but refer to the same location
	// after filepath.Clean. Both must pass validation.
	canonical := "/home/user/.ssh/authorized_keys"
	dotty := "/home/user/./extra/../.ssh/authorized_keys"

	if err := ValidateAuthorizedKeysPath(canonical); err != nil {
		t.Fatalf("canonical path rejected: %v", err)
	}
	if err := ValidateAuthorizedKeysPath(dotty); err != nil {
		t.Fatalf("dot-segment path rejected (should be cleaned to valid): %v", err)
	}

	// Confirm the two raw strings differ, so the test is meaningful.
	if canonical == dotty {
		t.Fatal("test paths are identical; the normalisation test is vacuous")
	}
}

// TestValidateAuthorizedKeysPathRuntime_ValidPath verifies that a real path
// under an allowed directory passes runtime validation.
func TestValidateAuthorizedKeysPathRuntime_ValidPath(t *testing.T) {
	// Create a real temporary directory so EvalSymlinks can resolve it.
	base := t.TempDir()

	// On macOS, t.TempDir() returns a path under /var/folders/... which is
	// itself a symlink to /private/var/folders/.... EvalSymlinks will resolve
	// to the /private/... form, so we must register the resolved base as the
	// allowed prefix; otherwise the runtime check would reject the path.
	resolvedBase, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatalf("EvalSymlinks on temp dir: %v", err)
	}

	// Temporarily prepend the resolved temp dir root to AllowedPathPrefixes so
	// the runtime validator accepts paths under it. Restore the original slice
	// when the test exits.
	orig := AllowedPathPrefixes
	t.Cleanup(func() { AllowedPathPrefixes = orig })
	AllowedPathPrefixes = append([]string{resolvedBase + "/"}, orig...)

	sshDir := filepath.Join(base, ".ssh")
	if err := os.MkdirAll(sshDir, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	target := filepath.Join(sshDir, "authorized_keys")
	if err := ValidateAuthorizedKeysPathRuntime(target); err != nil {
		t.Errorf("expected no error for valid real path, got: %v", err)
	}
}

// TestValidateAuthorizedKeysPathRuntime_SymlinkDetection verifies that a
// directory symlink that points outside the allowed prefixes is rejected.
func TestValidateAuthorizedKeysPathRuntime_SymlinkDetection(t *testing.T) {
	// Build the following layout in a temp dir:
	//
	//   <tmp>/real/          — the actual directory (outside allowed prefixes)
	//   <tmp>/allowed/link   — symlink pointing at <tmp>/real/
	//
	// We register <tmp>/allowed/ as an allowed prefix so that the lexical
	// check passes. The runtime check must then detect that the resolved path
	// falls under <tmp>/real/, which is NOT in the allowed set, and reject it.

	base := t.TempDir()

	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatalf("mkdir real: %v", err)
	}

	allowedDir := filepath.Join(base, "allowed")
	if err := os.MkdirAll(allowedDir, 0o700); err != nil {
		t.Fatalf("mkdir allowed: %v", err)
	}

	linkDir := filepath.Join(allowedDir, "link")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Skipf("cannot create symlink (unsupported on this platform/env): %v", err)
	}

	orig := AllowedPathPrefixes
	t.Cleanup(func() { AllowedPathPrefixes = orig })
	// Register only the raw allowedDir subtree as permitted. The lexical check
	// compares raw paths, so target (which starts with allowedDir) will pass.
	// The runtime check resolves the symlink; linkDir resolves to realDir, which
	// starts with base+"/real" — not base+"/allowed" — and is therefore rejected.
	AllowedPathPrefixes = []string{allowedDir + "/"}

	target := filepath.Join(linkDir, "authorized_keys")

	// Lexical check should pass: the raw target path starts with allowedDir.
	if err := ValidateAuthorizedKeysPath(target); err != nil {
		t.Fatalf("lexical check should pass, got: %v", err)
	}

	// Runtime check must fail: linkDir resolves to realDir, which is not under
	// the allowed prefix.
	if err := ValidateAuthorizedKeysPathRuntime(target); err == nil {
		t.Error("expected runtime validation to reject symlinked path outside allowed directories, got nil")
	} else if !containsStr(err.Error(), "resolves outside allowed directories") {
		t.Errorf("unexpected error message: %v", err)
	}
}

// TestValidateAuthorizedKeysPathRuntime_NonexistentDir verifies that a path
// whose parent directory does not exist causes a descriptive error from the
// runtime validator.
func TestValidateAuthorizedKeysPathRuntime_NonexistentDir(t *testing.T) {
	orig := AllowedPathPrefixes
	t.Cleanup(func() { AllowedPathPrefixes = orig })
	AllowedPathPrefixes = []string{"/home/"}

	// The directory /home/definitely-does-not-exist-lockwave-test/ should not
	// exist on any reasonable system.
	target := "/home/definitely-does-not-exist-lockwave-test/.ssh/authorized_keys"
	err := ValidateAuthorizedKeysPathRuntime(target)
	if err == nil {
		t.Skip("directory unexpectedly exists; skipping")
	}
	if !containsStr(err.Error(), "cannot resolve directory") {
		t.Errorf("expected 'cannot resolve directory' error, got: %v", err)
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
