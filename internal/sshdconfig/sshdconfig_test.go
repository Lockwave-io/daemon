package sshdconfig

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func testLogger() *logrus.Logger {
	l := logrus.New()
	l.SetOutput(os.Stderr)
	l.SetLevel(logrus.DebugLevel)
	return l
}

func testManager(t *testing.T) *Manager {
	t.Helper()
	dir := t.TempDir()
	return &Manager{
		DropInDir:  dir,
		DropInFile: DefaultDropInFile,
		RunCommand: func(name string, args ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
	}
}

func TestApply_BlocksPasswordAuth(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	changed, err := m.Apply(true, logger)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true for first write")
	}

	data, err := os.ReadFile(m.filePath())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	content := string(data)
	if !strings.Contains(content, "PasswordAuthentication no") {
		t.Errorf("expected 'PasswordAuthentication no', got:\n%s", content)
	}
	if !strings.Contains(content, "Managed by Lockwave") {
		t.Error("expected header comment")
	}
}

func TestApply_AllowsPasswordAuth(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	changed, err := m.Apply(false, logger)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true for first write")
	}

	data, err := os.ReadFile(m.filePath())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(data), "PasswordAuthentication yes") {
		t.Errorf("expected 'PasswordAuthentication yes', got:\n%s", string(data))
	}
}

func TestApply_Idempotent(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	// First apply
	changed, err := m.Apply(true, logger)
	if err != nil {
		t.Fatalf("first Apply() error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true on first apply")
	}

	// Second apply with same value
	cmdCalls := 0
	m.RunCommand = func(name string, args ...string) ([]byte, error) {
		cmdCalls++
		return []byte("ok"), nil
	}

	changed, err = m.Apply(true, logger)
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if changed {
		t.Fatal("expected changed=false for idempotent apply")
	}
	if cmdCalls != 0 {
		t.Errorf("expected no commands on idempotent apply, got %d", cmdCalls)
	}
}

func TestApply_ChangesExistingValue(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	// Set to block
	if _, err := m.Apply(true, logger); err != nil {
		t.Fatalf("first Apply() error: %v", err)
	}

	// Change to allow
	changed, err := m.Apply(false, logger)
	if err != nil {
		t.Fatalf("second Apply() error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true when changing value")
	}

	data, err := os.ReadFile(m.filePath())
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !strings.Contains(string(data), "PasswordAuthentication yes") {
		t.Errorf("expected 'PasswordAuthentication yes' after change, got:\n%s", string(data))
	}
}

func TestApply_RollbackOnValidationFailure(t *testing.T) {
	m := testManager(t)
	m.RunCommand = func(name string, args ...string) ([]byte, error) {
		if name == "sshd" {
			return []byte("sshd_config: bad config"), fmt.Errorf("exit 1")
		}
		return []byte("ok"), nil
	}
	logger := testLogger()

	_, err := m.Apply(true, logger)
	if err == nil {
		t.Fatal("expected error on validation failure")
	}
	if !strings.Contains(err.Error(), "validation failed") {
		t.Errorf("expected validation error, got: %v", err)
	}

	// File should have been rolled back
	if _, statErr := os.Stat(m.filePath()); !os.IsNotExist(statErr) {
		t.Error("expected drop-in file to be removed after rollback")
	}
}

func TestCurrent_NoFile(t *testing.T) {
	m := testManager(t)

	blocked, exists, err := m.Current()
	if err != nil {
		t.Fatalf("Current() error: %v", err)
	}
	if exists {
		t.Error("expected exists=false for missing file")
	}
	if blocked {
		t.Error("expected blocked=false for missing file")
	}
}

func TestCurrent_ReadsExisting(t *testing.T) {
	m := testManager(t)
	content := fileHeader + "PasswordAuthentication no\n"
	if err := os.WriteFile(m.filePath(), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	blocked, exists, err := m.Current()
	if err != nil {
		t.Fatalf("Current() error: %v", err)
	}
	if !exists {
		t.Error("expected exists=true")
	}
	if !blocked {
		t.Error("expected blocked=true for 'PasswordAuthentication no'")
	}
}

func TestCurrent_ReadsAllowed(t *testing.T) {
	m := testManager(t)
	content := fileHeader + "PasswordAuthentication yes\n"
	if err := os.WriteFile(m.filePath(), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	blocked, exists, err := m.Current()
	if err != nil {
		t.Fatalf("Current() error: %v", err)
	}
	if !exists {
		t.Error("expected exists=true")
	}
	if blocked {
		t.Error("expected blocked=false for 'PasswordAuthentication yes'")
	}
}

func TestRemove_CleansUp(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	// Create the file first
	content := fileHeader + "PasswordAuthentication no\n"
	if err := os.WriteFile(m.filePath(), []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	if err := m.Remove(logger); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}

	if _, err := os.Stat(m.filePath()); !os.IsNotExist(err) {
		t.Error("expected file to be removed")
	}
}

func TestRemove_NoFile(t *testing.T) {
	m := testManager(t)
	logger := testLogger()

	// Should not error when file doesn't exist
	if err := m.Remove(logger); err != nil {
		t.Fatalf("Remove() error: %v", err)
	}
}

func TestApply_CreatesDropInDir(t *testing.T) {
	dir := t.TempDir()
	subDir := filepath.Join(dir, "sshd_config.d")
	m := &Manager{
		DropInDir:  subDir,
		DropInFile: DefaultDropInFile,
		RunCommand: func(name string, args ...string) ([]byte, error) {
			return []byte("ok"), nil
		},
	}
	logger := testLogger()

	changed, err := m.Apply(true, logger)
	if err != nil {
		t.Fatalf("Apply() error: %v", err)
	}
	if !changed {
		t.Fatal("expected changed=true")
	}

	info, err := os.Stat(subDir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected drop-in dir to be created")
	}
}
