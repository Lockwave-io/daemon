package update

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

const downloadTimeout = 5 * time.Minute

// Apply downloads the binary from url and atomically replaces the current executable.
// The current executable path is resolved via os.Executable(). On success the caller
// should exit (e.g. os.Exit(0)) so systemd or the process manager restarts the new binary.
func Apply(url string, logger *slog.Logger) error {
	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("update: resolve executable: %w", err)
	}

	dir := filepath.Dir(selfPath)
	tmpPath := filepath.Join(dir, ".lockwaved.new."+fmt.Sprintf("%d", os.Getpid()))

	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("update: download %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("update: download returned status %d: %s", resp.StatusCode, string(body))
	}

	tmpFile, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return fmt.Errorf("update: create temp file: %w", err)
	}

	written, err := io.Copy(tmpFile, resp.Body)
	if err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("update: write temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		tmpFile.Close()
		os.Remove(tmpPath)
		return fmt.Errorf("update: sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("update: close temp file: %w", err)
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("update: rename over executable: %w", err)
	}

	logger.Info("update applied", "url", url, "bytes", written, "path", selfPath)
	return nil
}
