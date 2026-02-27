package telemetry

import (
	"log/slog"
	"os"
)

// NewLogger creates a structured JSON logger for the daemon.
func NewLogger(level slog.Level) *slog.Logger {
	opts := &slog.HandlerOptions{
		Level: level,
	}
	handler := slog.NewJSONHandler(os.Stderr, opts)
	return slog.New(handler)
}
