package config

import (
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
		{name: "path traversal rejected", path: "/home/user/../etc/shadow", wantErr: true, errMsg: "must not contain '..'"},
		{name: "outside allowed dirs", path: "/etc/shadow", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		{name: "wrong filename outside .ssh", path: "/home/user/keys", wantErr: true, errMsg: "must end with 'authorized_keys'"},
		{name: "/tmp rejected", path: "/tmp/authorized_keys", wantErr: true, errMsg: "outside allowed directories"},
		{name: "absolute but traversal", path: "/home/user/../../etc/passwd", wantErr: true, errMsg: "must not contain '..'"},
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

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
