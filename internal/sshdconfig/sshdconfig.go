package sshdconfig

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"

	"github.com/lockwave-io/daemon/internal/system"
)

const (
	DefaultDropInDir  = "/etc/ssh/sshd_config.d"
	DefaultDropInFile = "99-lockwave.conf"
)

const fileHeader = "# Managed by Lockwave daemon — do not edit manually.\n# Changes will be overwritten on next sync cycle.\n"

// Manager handles sshd drop-in configuration with configurable paths and
// command execution for testability.
type Manager struct {
	DropInDir  string
	DropInFile string
	RunCommand func(name string, args ...string) ([]byte, error)
}

// defaultRunCommand executes system commands using hardcoded binary paths.
func defaultRunCommand(name string, args ...string) ([]byte, error) {
	switch name {
	case "sshd":
		return exec.Command("sshd", args...).CombinedOutput() // #nosec G204 -- args are hardcoded by callers
	case "systemctl":
		return exec.Command("systemctl", args...).CombinedOutput() // #nosec G204 -- args are hardcoded by callers
	case "pidof":
		return exec.Command("pidof", args...).CombinedOutput() // #nosec G204 -- args are hardcoded by callers
	case "kill":
		return exec.Command("kill", args...).CombinedOutput() // #nosec G204 -- args are hardcoded by callers
	default:
		return nil, fmt.Errorf("unsupported command: %s", name)
	}
}

// DefaultManager returns a Manager with production paths and real command execution.
func DefaultManager() *Manager {
	return &Manager{
		DropInDir:  DefaultDropInDir,
		DropInFile: DefaultDropInFile,
		RunCommand: defaultRunCommand,
	}
}

func (m *Manager) filePath() string {
	return filepath.Join(m.DropInDir, m.DropInFile)
}

// Apply ensures the sshd drop-in config reflects the desired policy.
// Returns (changed bool, err error). Skips write+reload when file already matches.
func (m *Manager) Apply(blockPasswordAuth bool, logger *logrus.Logger) (bool, error) {
	blocked, exists, err := m.Current()
	if err != nil {
		return false, fmt.Errorf("read current state: %w", err)
	}

	if exists && blocked == blockPasswordAuth {
		return false, nil
	}

	content := m.buildContent(blockPasswordAuth)

	if err := system.EnsureDir(m.DropInDir, 0o755); err != nil {
		return false, fmt.Errorf("ensure drop-in dir: %w", err)
	}

	path := m.filePath()
	if err := system.AtomicWrite(path, []byte(content), 0o644); err != nil {
		return false, fmt.Errorf("write drop-in: %w", err)
	}

	// Validate sshd config — rollback on failure
	if out, err := m.RunCommand("sshd", "-t"); err != nil {
		_ = os.Remove(path)
		return false, fmt.Errorf("sshd config validation failed (rolled back): %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Reload sshd — try systemctl first, fall back to HUP signal
	if err := m.reloadSSHD(logger); err != nil {
		return false, fmt.Errorf("reload sshd: %w", err)
	}

	return true, nil
}

// Current reads the drop-in file and returns the current PasswordAuthentication value.
func (m *Manager) Current() (blocked bool, exists bool, err error) {
	data, err := os.ReadFile(m.filePath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, fmt.Errorf("read drop-in: %w", err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) == 2 && strings.EqualFold(parts[0], "PasswordAuthentication") {
			return strings.EqualFold(parts[1], "no"), true, nil
		}
	}

	// File exists but has no PasswordAuthentication directive
	return false, true, nil
}

// Remove deletes the drop-in file and reloads sshd (cleanup on deregistration).
func (m *Manager) Remove(logger *logrus.Logger) error {
	path := m.filePath()
	if err := os.Remove(path); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("remove drop-in: %w", err)
	}

	if err := m.reloadSSHD(logger); err != nil {
		logger.WithError(err).Warn("failed to reload sshd after removing drop-in")
	}

	return nil
}

func (m *Manager) buildContent(blockPasswordAuth bool) string {
	value := "yes"
	if blockPasswordAuth {
		value = "no"
	}
	return fileHeader + "PasswordAuthentication " + value + "\n"
}

func (m *Manager) reloadSSHD(logger *logrus.Logger) error {
	// Try "sshd" first (RHEL/CentOS/Fedora/Arch), then "ssh" (Debian/Ubuntu)
	for _, unit := range []string{"sshd", "ssh"} {
		if out, err := m.RunCommand("systemctl", "reload", unit); err == nil {
			logger.WithField("unit", unit).Debug("sshd reloaded via systemctl")
			return nil
		} else {
			logger.WithFields(logrus.Fields{
				"unit":   unit,
				"error":  err,
				"output": strings.TrimSpace(string(out)),
			}).Debug("systemctl reload failed")
		}
	}

	// Fallback: send HUP to sshd via pidof
	logger.Debug("trying kill -HUP fallback")
	pidOut, err := m.RunCommand("pidof", "sshd")
	if err != nil {
		return fmt.Errorf("pidof sshd failed: %w", err)
	}
	pid := strings.TrimSpace(strings.Fields(string(pidOut))[0])
	if _, err := m.RunCommand("kill", "-HUP", pid); err != nil {
		return fmt.Errorf("kill -HUP sshd (pid %s): %w", pid, err)
	}

	return nil
}

// Package-level convenience functions using the default manager.

// Apply ensures the sshd drop-in config reflects the desired policy.
func Apply(blockPasswordAuth bool, logger *logrus.Logger) (bool, error) {
	return DefaultManager().Apply(blockPasswordAuth, logger)
}

// Current reads the drop-in file and returns the current PasswordAuthentication value.
func Current() (blocked bool, exists bool, err error) {
	return DefaultManager().Current()
}

// Remove deletes the drop-in file and reloads sshd.
func Remove(logger *logrus.Logger) error {
	return DefaultManager().Remove(logger)
}
