package authorizedkeys

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParse_EmptyFile(t *testing.T) {
	path := writeTempFile(t, "")
	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if parsed.HasManagedBlock {
		t.Error("empty file should not have managed block")
	}
}

func TestParse_NonExistentFile(t *testing.T) {
	parsed, err := Parse("/nonexistent/path")
	if err != nil {
		t.Fatalf("unexpected error for nonexistent file: %v", err)
	}
	if parsed.HasManagedBlock {
		t.Error("nonexistent file should not have managed block")
	}
}

func TestParse_FileWithoutManagedBlock(t *testing.T) {
	content := "ssh-ed25519 AAAAC3Nza... user@laptop\nssh-rsa AAAAB3Nza... admin@work\n"
	path := writeTempFile(t, content)

	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if parsed.HasManagedBlock {
		t.Error("should not have managed block")
	}
	if len(parsed.PreBlock) != 2 {
		t.Errorf("pre-block lines = %d, want 2", len(parsed.PreBlock))
	}
}

func TestParse_FileWithManagedBlock(t *testing.T) {
	content := `ssh-ed25519 AAAAC3Nza... user@laptop
# --- BEGIN LOCKWAVE MANAGED BLOCK ---
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... managed-key-1
ssh-rsa AAAAB3NzaC1yc2EAAA... managed-key-2
# --- END LOCKWAVE MANAGED BLOCK ---
ssh-rsa AAAAB3Nza... admin@work
`
	path := writeTempFile(t, content)

	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !parsed.HasManagedBlock {
		t.Error("should have managed block")
	}
	if len(parsed.PreBlock) != 1 {
		t.Errorf("pre-block lines = %d, want 1", len(parsed.PreBlock))
	}
	if len(parsed.ManagedKeys) != 2 {
		t.Errorf("managed keys = %d, want 2", len(parsed.ManagedKeys))
	}
	if len(parsed.PostBlock) != 1 {
		t.Errorf("post-block lines = %d, want 1", len(parsed.PostBlock))
	}
}

func TestParse_ManagedBlockIgnoresComments(t *testing.T) {
	content := `# --- BEGIN LOCKWAVE MANAGED BLOCK ---
# This is a comment inside the block
ssh-ed25519 AAAAC3Nza... key1
# --- END LOCKWAVE MANAGED BLOCK ---
`
	path := writeTempFile(t, content)

	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(parsed.ManagedKeys) != 1 {
		t.Errorf("managed keys = %d, want 1 (comments should be excluded)", len(parsed.ManagedKeys))
	}
}

func TestParse_ManagedBlockIgnoresEmptyLines(t *testing.T) {
	content := `# --- BEGIN LOCKWAVE MANAGED BLOCK ---

ssh-ed25519 AAAAC3Nza... key1

# --- END LOCKWAVE MANAGED BLOCK ---
`
	path := writeTempFile(t, content)

	parsed, err := Parse(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(parsed.ManagedKeys) != 1 {
		t.Errorf("managed keys = %d, want 1 (empty lines should be excluded)", len(parsed.ManagedKeys))
	}
}

func writeTempFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "authorized_keys")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	return path
}
