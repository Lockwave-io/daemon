package drift

import (
	"sync"

	"github.com/lockwave-io/daemon/internal/authorizedkeys"
)

// Detector tracks post-apply state hashes and detects external modifications
// to the managed block in authorized_keys files.
type Detector struct {
	mu     sync.Mutex
	hashes map[string]string // keyed by OS user
}

// NewDetector creates a Detector with no stored hashes.
func NewDetector() *Detector {
	return &Detector{hashes: make(map[string]string)}
}

// RecordApplied computes and stores the SHA-256 hash of the managed block at
// path after a successful Apply. The hash is keyed by osUser.
func (d *Detector) RecordApplied(osUser, path string) error {
	h, err := authorizedkeys.HashManagedBlock(path)
	if err != nil {
		return err
	}
	d.mu.Lock()
	d.hashes[osUser] = h
	d.mu.Unlock()
	return nil
}

// Check re-reads the authorized_keys file at path and compares its current
// managed block hash against the stored post-apply hash for osUser.
// Returns true if drift is detected (hashes differ).
// Returns false if no prior hash is stored (first run) or hashes match.
func (d *Detector) Check(osUser, path string) (bool, error) {
	d.mu.Lock()
	prev, ok := d.hashes[osUser]
	d.mu.Unlock()

	if !ok {
		return false, nil // no baseline yet
	}

	current, err := authorizedkeys.HashManagedBlock(path)
	if err != nil {
		return false, err
	}

	// Empty hash means no managed block; if we previously had one, that's drift
	if current == "" && prev != "" {
		return true, nil
	}

	return current != prev, nil
}

// Reset clears all stored hashes (e.g. after a config change).
func (d *Detector) Reset() {
	d.mu.Lock()
	d.hashes = make(map[string]string)
	d.mu.Unlock()
}
