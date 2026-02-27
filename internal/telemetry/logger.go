package telemetry

import (
	"os"

	"github.com/sirupsen/logrus"
)

// NewLogger creates a structured JSON logger for the daemon.
func NewLogger(debug bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(os.Stderr)
	logger.SetFormatter(&logrus.JSONFormatter{})

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}
