package daemon

import "errors"

// Sentinel errors for the daemon.
var (
	// ErrConfigInvalid indicates a configuration validation failure.
	ErrConfigInvalid = errors.New("lockwave: config invalid")

	// ErrSyncFailed indicates a sync communication failure.
	ErrSyncFailed = errors.New("lockwave: sync failed")

	// ErrDriftDetected indicates the managed block was modified externally.
	ErrDriftDetected = errors.New("lockwave: drift detected")

	// ErrUpdateFailed indicates an update download or verification failure.
	ErrUpdateFailed = errors.New("lockwave: update failed")
)
