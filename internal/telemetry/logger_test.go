package telemetry

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(slog.LevelInfo)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	// Should not panic
	logger.Info("test message")
}

func TestNewLogger_output(t *testing.T) {
	var buf bytes.Buffer
	opts := &slog.HandlerOptions{Level: slog.LevelInfo}
	handler := slog.NewJSONHandler(&buf, opts)
	logger := slog.New(handler)
	logger.Info("hello", "key", "value")
	out := buf.String()
	if out == "" {
		t.Error("expected JSON output")
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "key") {
		t.Errorf("unexpected output: %s", out)
	}
}
