package update

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// tempFilePerms is the permission used while the downloaded binary is being
// written and validated. Only the daemon user may access it during this
// window, preventing other processes from racing on the file.
const tempFilePerms = 0o700

// finalFilePerms is the permission applied to the temp file immediately before
// it is atomically renamed over the running executable. This matches the
// expected permissions of an installed daemon binary.
const finalFilePerms = 0o755

const downloadTimeout = 5 * time.Minute

// Apply downloads the binary from url and atomically replaces the current executable.
// The checksum (SHA-256 hex) is mandatory and verified after download.
// The URL must use HTTPS. The current executable path is resolved via os.Executable().
// On success the caller should exit (e.g. os.Exit(0)) so systemd or the process manager
// restarts the new binary.
func Apply(url, checksum string, logger *logrus.Logger) error {
	if checksum == "" {
		return fmt.Errorf("update: checksum is required but was empty")
	}

	if !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("update: refusing non-HTTPS update URL: %s", url)
	}

	selfPath, err := os.Executable()
	if err != nil {
		return fmt.Errorf("update: resolve executable: %w", err)
	}

	dir := filepath.Dir(selfPath)

	// Use os.CreateTemp with a random suffix to avoid predictable temp paths
	// and eliminate the TOCTOU window that a fixed pid-based name would create.
	// #nosec G304 -- dir is derived from os.Executable(), not user input
	tmpFile, err := os.CreateTemp(dir, ".lockwaved.new.*")
	if err != nil {
		return fmt.Errorf("update: create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()

	// Restrict access to the daemon user only while the file is being written
	// and validated. This prevents other processes from reading or executing
	// the partially-written binary during the validation window.
	if err := tmpFile.Chmod(tempFilePerms); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: chmod temp file: %w", err)
	}

	client := &http.Client{Timeout: downloadTimeout}
	resp, err := client.Get(url)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: download %s: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("update: download returned status %d: %s", resp.StatusCode, string(body))
	}

	// Write to temp file while computing hash
	hasher := sha256.New()
	writer := io.MultiWriter(tmpFile, hasher)

	written, err := io.Copy(writer, resp.Body)
	if err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: write temp file: %w", err)
	}

	if err := tmpFile.Sync(); err != nil {
		_ = tmpFile.Close()
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: sync temp file: %w", err)
	}

	if err := tmpFile.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: close temp file: %w", err)
	}

	// Validate file size
	if written == 0 {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: downloaded file is empty")
	}

	// Verify checksum (mandatory)
	gotHash := hex.EncodeToString(hasher.Sum(nil))
	if gotHash != checksum {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: checksum mismatch: expected %s, got %s", checksum, gotHash)
	}
	logger.WithField("sha256", gotHash).Info("update checksum verified")

	// Validate the binary by running "version" subcommand
	out, err := exec.Command(tmpPath, "version").CombinedOutput() // #nosec G204 -- tmpPath is from os.CreateTemp in the executable's own directory, not user input
	if err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: binary validation failed (not a valid lockwaved binary): %w: %s", err, string(out))
	}
	logger.WithField("output", string(out)).Debug("update binary validated")

	// Widen permissions to world-executable before the atomic rename so the
	// installed binary has the expected 0o755 mode from the very first moment
	// it replaces the running executable.
	if err := os.Chmod(tmpPath, finalFilePerms); err != nil { // #nosec G302 -- binary must be world-executable
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: chmod final temp file: %w", err)
	}

	if err := os.Rename(tmpPath, selfPath); err != nil {
		_ = os.Remove(tmpPath)
		return fmt.Errorf("update: rename over executable: %w", err)
	}

	logger.WithFields(logrus.Fields{
		"url":    url,
		"bytes":  written,
		"sha256": gotHash,
		"path":   selfPath,
	}).Info("update applied")
	return nil
}
