package authorizedkeys

import (
	"bufio"
	"os"
	"strings"
)

const (
	// DefaultBeginMarker is the start delimiter for the managed block.
	DefaultBeginMarker = "# --- BEGIN LOCKWAVE MANAGED BLOCK ---"
	// DefaultEndMarker is the end delimiter for the managed block.
	DefaultEndMarker = "# --- END LOCKWAVE MANAGED BLOCK ---"
)

// ParsedFile represents a parsed authorized_keys file split into sections.
type ParsedFile struct {
	// PreBlock contains lines before the managed block.
	PreBlock []string
	// ManagedKeys contains the public key lines within the managed block.
	ManagedKeys []string
	// PostBlock contains lines after the managed block.
	PostBlock []string
	// HasManagedBlock indicates whether a managed block was found.
	HasManagedBlock bool
}

// Parse reads an authorized_keys file and splits it into managed and unmanaged sections.
func Parse(path string) (*ParsedFile, error) {
	f, err := os.Open(path) // #nosec G304 -- path is from daemon config (CLI flag or default), not user-controlled web input
	if err != nil {
		if os.IsNotExist(err) {
			return &ParsedFile{}, nil
		}
		return nil, err
	}
	defer func() { _ = f.Close() }()

	var result ParsedFile
	scanner := bufio.NewScanner(f)

	section := "pre" // "pre", "managed", "post"
	for scanner.Scan() {
		line := scanner.Text()

		switch section {
		case "pre":
			if strings.TrimSpace(line) == DefaultBeginMarker {
				section = "managed"
				result.HasManagedBlock = true
				continue
			}
			result.PreBlock = append(result.PreBlock, line)

		case "managed":
			if strings.TrimSpace(line) == DefaultEndMarker {
				section = "post"
				continue
			}
			trimmed := strings.TrimSpace(line)
			if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				result.ManagedKeys = append(result.ManagedKeys, trimmed)
			}

		case "post":
			result.PostBlock = append(result.PostBlock, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return &result, nil
}

// ExtractFingerprints returns a list of key fingerprints from the managed block.
// This is a simplified implementation — in production, you'd parse the actual
// public key to compute SHA256 fingerprints.
func (p *ParsedFile) ExtractFingerprints() []string {
	// For the observed state report, we return the raw key lines.
	// The server compares by fingerprint, but the daemon reports what it sees.
	return p.ManagedKeys
}
