// File: internal/observability/logger.go
package observability

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// globalLogger stores the global logger instance safely across goroutines.
	globalLogger atomic.Pointer[zap.Logger]
	// once ensures that initialization happens exactly once.
	once sync.Once
)

// ANSI color codes for the terminal.
const (
	colorBlack   = "\x1b[30m"
	colorRed     = "\x1b[31m"
	colorGreen   = "\x1b[32m"
	colorYellow  = "\x1b[33m"
	colorBlue    = "\x1b[34m"
	colorMagenta = "\x1b[35m"
	colorCyan    = "\x1b[36m"
	colorWhite   = "\x1b[37m"
	colorReset   = "\x1b[0m"
)

// colorMap translates friendly names to ANSI codes.
var colorMap = map[string]string{
	"black":   colorBlack,
	"red":     colorRed,
	"green":   colorGreen,
	"yellow":  colorYellow,
	"blue":    colorBlue,
	"magenta": colorMagenta,
	"cyan":    colorCyan,
	"white":   colorWhite,
}

// Initialize sets up the global Zap logger based on configuration and a specified output writer.
// This is the core, flexible initializer.
func Initialize(cfg config.LoggerConfig, consoleWriter zapcore.WriteSyncer) {
	// Ensures initialization logic runs only once.
	once.Do(func() {
		level := zap.NewAtomicLevel()
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			level.SetLevel(zap.InfoLevel)
		}

		consoleEncoder := getEncoder(cfg)
		consoleCore := zapcore.NewCore(consoleEncoder, consoleWriter, level)
		cores := []zapcore.Core{consoleCore}

		if cfg.LogFile != "" {
			// File encoder is always JSON for structured logging.
			fileEncoder := getEncoder(config.LoggerConfig{Format: "json"})
			// lumberjack handles file rotation and thread-safe writes.
			fileWriter := zapcore.AddSync(&lumberjack.Logger{
				Filename:   cfg.LogFile,
				MaxSize:    cfg.MaxSize,
				MaxBackups: cfg.MaxBackups,
				MaxAge:     cfg.MaxAge,
				Compress:   cfg.Compress,
			})
			fileCore := zapcore.NewCore(fileEncoder, fileWriter, level)
			cores = append(cores, fileCore)
		}

		core := zapcore.NewTee(cores...)
		options := []zap.Option{zap.AddStacktrace(zap.ErrorLevel)}
		if cfg.AddSource {
			options = append(options, zap.AddCaller())
		}

		logger := zap.New(core, options...).Named(cfg.ServiceName)
		globalLogger.Store(logger) // Atomically store the initialized logger.

		// Replace the standard library logger and Zap's global loggers.
		zap.ReplaceGlobals(logger)
		zap.RedirectStdLog(logger)
	})
}

// InitializeLogger is a convenience wrapper around Initialize for production use.
// It defaults console output to a locked Stdout.
func InitializeLogger(cfg config.LoggerConfig) {
	Initialize(cfg, zapcore.Lock(os.Stdout))
}

// ResetForTest resets the sync.Once and clears the global logger.
// This function should ONLY be used in tests to ensure isolation.
func ResetForTest() {
	globalLogger.Store(nil)
	once = sync.Once{}
}

// newColorizedLevelEncoder creates a zapcore.LevelEncoder that colorizes the log level.
func newColorizedLevelEncoder(colors config.ColorConfig) zapcore.LevelEncoder {
	return func(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {
		var color string
		levelStr := strings.ToUpper(level.String())

		switch level {
		case zapcore.DebugLevel:
			color = colorMap[colors.Debug]
		case zapcore.InfoLevel:
			color = colorMap[colors.Info]
		case zapcore.WarnLevel:
			color = colorMap[colors.Warn]
		case zapcore.ErrorLevel:
			color = colorMap[colors.Error]
		case zapcore.DPanicLevel:
			color = colorMap[colors.DPanic]
		case zapcore.PanicLevel:
			color = colorMap[colors.Panic]
		case zapcore.FatalLevel:
			color = colorMap[colors.Fatal]
		default:
			color = colorReset
		}

		if color != "" {
			enc.AppendString(fmt.Sprintf("%s%s%s", color, levelStr, colorReset))
		} else {
			enc.AppendString(levelStr)
		}
	}
}

// getEncoder selects and configures the appropriate log encoder based on the
// provided configuration. It supports "json" for structured logging and a custom
// "console" format for human-readable, colorized terminal output.
func getEncoder(cfg config.LoggerConfig) zapcore.Encoder {
	// --- Base Configuration ---
	// Start with production-ready encoder settings.
	encoderConfig := zap.NewProductionEncoderConfig()
	// Use a more human-readable time format.
	encoderConfig.EncodeTime = zapcore.TimeEncoderOfLayout("2006-01-02T15:04:05.000Z07:00")

	// --- Console Format ---
	// The console format is optimized for readability in a terminal.
	if cfg.Format == "console" {
		// Enable colorized log levels for better visual distinction.
		encoderConfig.EncodeLevel = newColorizedLevelEncoder(cfg.Colors)

		// Customize the encoder to create a clean, single-line log message.
		// This avoids the multi-line, key-value output of the default console encoder.
		return newCustomConsoleEncoder(encoderConfig)
	}

	// --- JSON Format (Default) ---
	// The JSON format is ideal for production environments where logs are parsed
	// by log management systems (e.g., ELK, Splunk, Datadog).
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder // e.g., "INFO", "ERROR"
	return zapcore.NewJSONEncoder(encoderConfig)
}

// newCustomConsoleEncoder creates a Zap encoder with a custom format optimized for
// human readability in a terminal. It produces a clean, single-line output that
// includes the timestamp, a color-coded level, the logger's name (component),
// the main message, and any structured fields as a JSON blob.
func newCustomConsoleEncoder(cfg zapcore.EncoderConfig) zapcore.Encoder {
	// We create a new encoder configuration to avoid modifying the original.
	// This ensures that if the original cfg is used elsewhere, it remains unchanged.
	consoleCfg := cfg
	// The `EncodeName` is customized to add a dot suffix, making the component
	// name visually distinct in the log line (e.g., "scalpel-cli.DiscoveryEngine.").
	consoleCfg.EncodeName = func(loggerName string, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(loggerName + ".")
	}

	// The custom encoder is built on top of Zap's standard ConsoleEncoder.
	// By creating our own implementation, we gain full control over the final
	// log format, allowing us to structure the output exactly as desired.
	return zapcore.NewConsoleEncoder(consoleCfg)
}

// GetLogger returns the initialized global logger instance.
func GetLogger() *zap.Logger {
	logger := globalLogger.Load() // Atomically load the logger pointer.
	if logger == nil {
		// Fallback mechanism if InitializeLogger hasn't been called.
		l, err := zap.NewDevelopment()
		if err != nil {
			return zap.NewNop()
		}
		// Log a warning that the fallback is being used.
		l.Warn("Global logger requested before initialization; using fallback.")
		return l.Named("fallback")
	}
	return logger
}

// Sync flushes any buffered log entries. Applications should call this before exiting.
func Sync() {
	logger := globalLogger.Load()
	if logger != nil {
		if err := logger.Sync(); err != nil {
			// Handle common sync errors gracefully (e.g., writing to closed stdout/stderr on some OSes).
			// This prevents noisy errors during application shutdown or test teardown.
			errMsg := err.Error()
			if !strings.Contains(errMsg, "sync /dev/stdout") &&
				!strings.Contains(errMsg, "invalid argument") &&
				!strings.Contains(errMsg, "operation not supported") {
				fmt.Fprintln(os.Stderr, "Error: failed to sync logger:", err)
			}
		}
	}
}
