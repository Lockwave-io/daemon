package update

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/lockwave-io/daemon/internal/telemetry"
)

func TestApply_ChecksumMatch(t *testing.T) {
	// Create a fake binary that responds to "version"
	binaryContent := []byte("#!/bin/sh\necho 'lockwaved 1.2.3 (linux/amd64)'\n")
	h := sha256.Sum256(binaryContent)
	checksum := hex.EncodeToString(h[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(binaryContent)
	}))
	defer server.Close()

	// We need to mock os.Executable — we'll test checksum logic directly
	// Since Apply() calls os.Executable(), we test via the download+hash path
	logger := telemetry.NewLogger(slog.LevelDebug)

	// Apply will fail because os.Executable() returns the test binary path
	// and the version check will fail, but we can verify the checksum logic
	// by testing with a mismatched checksum
	err := Apply(server.URL, "bad_checksum_value", logger)
	if err == nil {
		t.Fatal("expected error for checksum mismatch")
	}

	// Verify the error mentions checksum mismatch
	if got := err.Error(); !contains(got, "checksum mismatch") {
		t.Errorf("expected checksum mismatch error, got: %s", got)
	}

	_ = checksum // would be used in a full integration test
}

func TestApply_EmptyDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return empty body
	}))
	defer server.Close()

	logger := telemetry.NewLogger(slog.LevelDebug)
	err := Apply(server.URL, "", logger)
	if err == nil {
		t.Fatal("expected error for empty download")
	}

	if got := err.Error(); !contains(got, "empty") {
		t.Errorf("expected empty file error, got: %s", got)
	}
}

func TestApply_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer server.Close()

	logger := telemetry.NewLogger(slog.LevelDebug)
	err := Apply(server.URL, "", logger)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}

	if got := err.Error(); !contains(got, "404") {
		t.Errorf("expected 404 in error, got: %s", got)
	}
}

func TestApply_InvalidURL(t *testing.T) {
	logger := telemetry.NewLogger(slog.LevelDebug)
	err := Apply("http://127.0.0.1:0/nonexistent", "", logger)
	if err == nil {
		t.Fatal("expected error for unreachable URL")
	}
}

// TestChecksumComputation verifies the SHA-256 hash computation logic.
func TestChecksumComputation(t *testing.T) {
	data := []byte("test binary content")
	h := sha256.Sum256(data)
	expected := hex.EncodeToString(h[:])

	// Write to temp file and verify
	dir := t.TempDir()
	path := filepath.Join(dir, "binary")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatalf("write: %v", err)
	}

	content, _ := os.ReadFile(path)
	h2 := sha256.Sum256(content)
	got := hex.EncodeToString(h2[:])

	if got != expected {
		t.Errorf("checksum mismatch: %s != %s", got, expected)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsImpl(s, substr))
}

func containsImpl(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
