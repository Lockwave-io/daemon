package telemetry

import (
	"bytes"
	"strings"
	"testing"

	"github.com/sirupsen/logrus"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(false)
	if logger == nil {
		t.Fatal("NewLogger returned nil")
	}
	// Should not panic
	logger.Info("test message")
}

func TestNewLogger_debug(t *testing.T) {
	logger := NewLogger(true)
	if logger.GetLevel() != logrus.DebugLevel {
		t.Errorf("expected debug level, got %v", logger.GetLevel())
	}
}

func TestNewLogger_output(t *testing.T) {
	var buf bytes.Buffer
	logger := logrus.New()
	logger.SetOutput(&buf)
	logger.SetFormatter(&logrus.JSONFormatter{})
	logger.WithField("key", "value").Info("hello")

	out := buf.String()
	if out == "" {
		t.Error("expected JSON output")
	}
	if !strings.Contains(out, "hello") || !strings.Contains(out, "key") {
		t.Errorf("unexpected output: %s", out)
	}
}
