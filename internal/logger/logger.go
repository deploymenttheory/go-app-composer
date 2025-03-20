package logger

import (
	"fmt"
	"path/filepath"

	"github.com/deploymenttheory/go-app-composer/internal/utils/fsutil"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// Global logger instance
var Logger *zap.SugaredLogger

// LoggerConfig contains configuration for the logger
type LoggerConfig struct {
	Debug     bool   // Enable debug level logging
	LogFormat string // "json" or "human"
	LogFile   string // Path to log file (optional)
}

// DefaultConfig returns a default configuration
func DefaultConfig() LoggerConfig {
	return LoggerConfig{
		Debug:     false,
		LogFormat: "human",
		LogFile:   "logs/tooling.log",
	}
}

// InitLogger initializes the logger with the provided configuration
func InitLogger(config LoggerConfig) error {
	var zapConfig zap.Config

	// Configure log format
	if config.LogFormat == "json" {
		zapConfig = zap.NewProductionConfig() // JSON logs for structured logging
	} else {
		zapConfig = zap.NewDevelopmentConfig()                                 // Human-readable logs with color
		zapConfig.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder // Enables colored log levels
	}

	// Configure output paths
	outputPaths := []string{"stdout"}
	if config.LogFile != "" {
		// Ensure log directory exists
		logDir := filepath.Dir(config.LogFile)
		if err := fsutil.CreateDirIfNotExists(logDir); err != nil {
			return fmt.Errorf("failed to create log directory: %w", err)
		}
		outputPaths = append(outputPaths, config.LogFile)
	}
	zapConfig.OutputPaths = outputPaths

	// Set log level dynamically
	if config.Debug {
		zapConfig.Level = zap.NewAtomicLevelAt(zap.DebugLevel)
	}

	// Build logger
	logger, err := zapConfig.Build()
	if err != nil {
		return fmt.Errorf("failed to initialize logger: %w", err)
	}

	// Assign global logger instance
	Logger = logger.Sugar()
	return nil
}

// SimpleInitLogger provides backward compatibility with the old init function
func SimpleInitLogger(debug bool, logFormat string) {
	config := LoggerConfig{
		Debug:     debug,
		LogFormat: logFormat,
		LogFile:   "logs/tooling.log",
	}

	err := InitLogger(config)
	if err != nil {
		panic("Failed to initialize logger: " + err.Error())
	}
}

// Log functions
func LogInfo(message string, fields map[string]interface{}) {
	Logger.Infow(message, flattenFields(fields)...)
}

func LogWarn(message string, fields map[string]interface{}) {
	Logger.Warnw(message, flattenFields(fields)...)
}

func LogError(message string, err error, fields map[string]interface{}) {
	if fields == nil {
		fields = make(map[string]interface{})
	}
	fields["error"] = err.Error()
	Logger.Errorw(message, flattenFields(fields)...)
}

func LogDebug(message string, fields map[string]interface{}) {
	Logger.Debugw(message, flattenFields(fields)...)
}

func LogFatal(message string, fields map[string]interface{}) {
	Logger.Fatalw(message, flattenFields(fields)...)
}

// WithField returns a logger with a field added to every log
func WithField(key string, value interface{}) *zap.SugaredLogger {
	return Logger.With(key, value)
}

// WithFields returns a logger with multiple fields added to every log
func WithFields(fields map[string]interface{}) *zap.SugaredLogger {
	return Logger.With(flattenFields(fields)...)
}

// WithError returns a logger with an error field added to every log
func WithError(err error) *zap.SugaredLogger {
	return Logger.With("error", err.Error())
}

// Helper function to format key-value pairs for logging
func flattenFields(fields map[string]interface{}) []interface{} {
	var flat []interface{}
	for k, v := range fields {
		flat = append(flat, k, v)
	}
	return flat
}

// Sync flushes any buffered log entries
func Sync() error {
	return Logger.Sync()
}
