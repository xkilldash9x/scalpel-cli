// -- pkg/observability/logger.go --
package observability

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic" // Import atomic

	"github.com/xkilldash9x/scalpel-cli/pkg/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"gopkg.in/natefinch/lumberjack.v2"
)

var (
	// Use an atomic pointer for safe concurrent access
	globalLogger atomic.Pointer[zap.Logger]
	once         sync.Once
)

// InitializeLogger sets up the global Zap logger based on the configuration.
func InitializeLogger(cfg config.LoggerConfig) {
	once.Do(func() {
		level := zap.NewAtomicLevel()
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			level.SetLevel(zap.InfoLevel)
		}

		consoleEncoder := getEncoder(cfg.Format)
		consoleCore := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), level)
		cores := []zapcore.Core{consoleCore}

		if cfg.LogFile != "" {
			fileEncoder := getEncoder("json")
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
		globalLogger.Store(logger) // Atomic store

		zap.ReplaceGlobals(logger)
		zap.RedirectStdLog(logger)
	})
}

func getEncoder(format string) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder

	if format == "console" {
		encoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		return zapcore.NewConsoleEncoder(encoderConfig)
	}
	return zapcore.NewJSONEncoder(encoderConfig)
}

// GetLogger returns the initialized global logger instance.
func GetLogger() *zap.Logger {
	logger := globalLogger.Load() // Atomic load
	if logger == nil {
		// Fallback mechanism
		l, err := zap.NewDevelopment()
		if err != nil {
			// Return NewNop() to prevent panic if development logger fails
			return zap.NewNop()
		}
		return l.Named("fallback")
	}
	return logger
}

// Sync flushes any buffered log entries.
func Sync() {
	logger := globalLogger.Load() // Atomic load
	if logger != nil {
		// Error is commonly ignored during shutdown, but log to stderr if critical.
		if err := logger.Sync(); err != nil {
			// Cannot rely on the logger itself, so print to stderr.
			fmt.Fprintln(os.Stderr, "Error: failed to sync logger:", err)
		}
	}
}