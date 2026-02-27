package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_ValidConfig(t *testing.T) {
	content := `api_url: https://lockwave.io
host_id: host-abc-123
credential: secret-credential-value
poll_seconds: 30
managed_users:
  - os_user: deploy
  - os_user: www-data
    authorized_keys_path: /var/www/.ssh/authorized_keys
`
	path := writeConfigFile(t, content, 0o600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if cfg.APIURL != "https://lockwave.io" {
		t.Errorf("api_url = %q", cfg.APIURL)
	}
	if cfg.HostID != "host-abc-123" {
		t.Errorf("host_id = %q", cfg.HostID)
	}
	if cfg.Credential != "secret-credential-value" {
		t.Errorf("credential = %q", cfg.Credential)
	}
	if cfg.PollSecs != 30 {
		t.Errorf("poll_seconds = %d, want 30", cfg.PollSecs)
	}
	if len(cfg.Users) != 2 {
		t.Fatalf("managed_users count = %d, want 2", len(cfg.Users))
	}
	if cfg.Users[0].OSUser != "deploy" {
		t.Errorf("user[0].os_user = %q", cfg.Users[0].OSUser)
	}
	if cfg.Users[1].AuthorizedKeysPath != "/var/www/.ssh/authorized_keys" {
		t.Errorf("user[1].authorized_keys_path = %q", cfg.Users[1].AuthorizedKeysPath)
	}
}

func TestLoad_InsecurePermissions(t *testing.T) {
	content := `api_url: https://example.com
host_id: h
credential: c
managed_users:
  - os_user: deploy
`
	path := writeConfigFile(t, content, 0o644)

	_, err := Load(path)
	if err == nil {
		t.Error("expected error for insecure permissions")
	}
}

func TestLoad_MissingRequiredFields(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"missing api_url", "host_id: h\ncredential: c\nmanaged_users:\n  - os_user: u\n"},
		{"missing host_id", "api_url: https://x\ncredential: c\nmanaged_users:\n  - os_user: u\n"},
		{"missing credential", "api_url: https://x\nhost_id: h\nmanaged_users:\n  - os_user: u\n"},
		{"missing users", "api_url: https://x\nhost_id: h\ncredential: c\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := writeConfigFile(t, tt.content, 0o600)
			_, err := Load(path)
			if err == nil {
				t.Errorf("expected validation error for %s", tt.name)
			}
		})
	}
}

func TestLoad_LowPollSecsDefaultsTo60(t *testing.T) {
	content := `api_url: https://example.com
host_id: h
credential: c
poll_seconds: 5
managed_users:
  - os_user: deploy
`
	path := writeConfigFile(t, content, 0o600)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if cfg.PollSecs != 60 {
		t.Errorf("poll_seconds = %d, want 60 (should default when < 10)", cfg.PollSecs)
	}
}

func TestSave_CreatesFileWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subdir", "config.yaml")

	cfg := &Config{
		APIURL:     "https://example.com",
		HostID:     "h",
		Credential: "c",
		PollSecs:   60,
		Users:      []ManagedUser{{OSUser: "deploy"}},
	}

	if err := Save(path, cfg); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("permissions = %o, want 0600", perm)
	}
}

func TestManagedUser_ResolveAuthorizedKeysPath(t *testing.T) {
	u1 := ManagedUser{OSUser: "deploy"}
	if got := u1.ResolveAuthorizedKeysPath(); got != "/home/deploy/.ssh/authorized_keys" {
		t.Errorf("default path = %q", got)
	}

	u2 := ManagedUser{OSUser: "www-data", AuthorizedKeysPath: "/var/www/.ssh/authorized_keys"}
	if got := u2.ResolveAuthorizedKeysPath(); got != "/var/www/.ssh/authorized_keys" {
		t.Errorf("custom path = %q", got)
	}
}

func writeConfigFile(t *testing.T, content string, perm os.FileMode) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), perm); err != nil {
		t.Fatalf("write config file: %v", err)
	}
	return path
}
