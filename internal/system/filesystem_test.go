package system

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	data := []byte("hello world")
	perm := os.FileMode(0644)

	if err := AtomicWrite(path, data, perm); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	read, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(read) != string(data) {
		t.Errorf("content mismatch: got %q", read)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != perm {
		t.Errorf("perm mismatch: got %o", info.Mode().Perm())
	}
}

func TestAtomicWrite_overwrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "overwrite.txt")
	if err := os.WriteFile(path, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	newData := []byte("new content")
	if err := AtomicWrite(path, newData, 0644); err != nil {
		t.Fatalf("AtomicWrite: %v", err)
	}
	read, _ := os.ReadFile(path)
	if string(read) != string(newData) {
		t.Errorf("content mismatch: got %q", read)
	}
}

func TestEnsureDir(t *testing.T) {
	dir := t.TempDir()
	sub := filepath.Join(dir, "a", "b", "c")
	if err := EnsureDir(sub, 0755); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	info, err := os.Stat(sub)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if !info.IsDir() {
		t.Error("expected directory")
	}
}

func TestEnsureDir_idempotent(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureDir(dir, 0755); err != nil {
		t.Fatalf("EnsureDir: %v", err)
	}
	if err := EnsureDir(dir, 0755); err != nil {
		t.Fatalf("EnsureDir again: %v", err)
	}
}
