package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Config holds all daemon configuration.
type Config struct {
	APIURL     string        `yaml:"api_url"`
	HostID     string        `yaml:"host_id"`
	Credential string        `yaml:"credential"`
	PollSecs   int           `yaml:"poll_seconds"`
	Users      []ManagedUser `yaml:"managed_users"`
}

// ManagedUser represents an OS user whose authorized_keys the daemon manages.
type ManagedUser struct {
	OSUser             string `yaml:"os_user"`
	AuthorizedKeysPath string `yaml:"authorized_keys_path,omitempty"`
}

// DefaultConfigPath is the standard location for the daemon config file.
const DefaultConfigPath = "/etc/lockwave/config.yaml"

// Load reads and parses the YAML config from the given path.
// It enforces that the file has restricted permissions (0600).
func Load(path string) (*Config, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("config: stat %s: %w", path, err)
	}

	perm := info.Mode().Perm()
	if perm&0o077 != 0 {
		return nil, fmt.Errorf("config: %s has insecure permissions %o (must be 0600)", path, perm)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// Save writes the config to the given path with 0600 permissions.
func Save(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("config: mkdir %s: %w", dir, err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("config: write %s: %w", path, err)
	}

	return nil
}

// Validate checks that all required fields are present.
func (c *Config) Validate() error {
	if c.APIURL == "" {
		return fmt.Errorf("config: api_url is required")
	}
	if c.HostID == "" {
		return fmt.Errorf("config: host_id is required")
	}
	if c.Credential == "" {
		return fmt.Errorf("config: credential is required")
	}
	if c.PollSecs < 10 {
		c.PollSecs = 60
	}
	if len(c.Users) == 0 {
		return fmt.Errorf("config: at least one managed_user is required")
	}
	return nil
}

// ResolveAuthorizedKeysPath returns the configured path or the default for the OS user.
func (u *ManagedUser) ResolveAuthorizedKeysPath() string {
	if u.AuthorizedKeysPath != "" {
		return u.AuthorizedKeysPath
	}
	return filepath.Join("/home", u.OSUser, ".ssh", "authorized_keys")
}
