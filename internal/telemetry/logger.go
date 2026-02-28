package telemetry

import (
	"os"

	"github.com/sirupsen/logrus"
	"gopkg.in/lumberjack.v2"
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

// NewFileLogger creates a structured JSON logger that writes to a file with
// automatic rotation. MaxSize is 1 MB, keeping 3 backups for up to 7 days,
// with gzip compression enabled.
func NewFileLogger(path string, debug bool) *logrus.Logger {
	logger := logrus.New()
	logger.SetOutput(&lumberjack.Logger{
		Filename:   path,
		MaxSize:    1, // megabytes
		MaxBackups: 3,
		MaxAge:     7, // days
		Compress:   true,
	})
	logger.SetFormatter(&logrus.JSONFormatter{})

	if debug {
		logger.SetLevel(logrus.DebugLevel)
	} else {
		logger.SetLevel(logrus.InfoLevel)
	}

	return logger
}
