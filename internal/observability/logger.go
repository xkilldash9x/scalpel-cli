// -- pkg/observability/logger.go --
package observability

import (
	"fmt"
	"os"
	"strings"
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

// InitializeLogger sets up the global Zap logger based on the configuration.
func InitializeLogger(cfg config.LoggerConfig) {
	once.Do(func() {
		level := zap.NewAtomicLevel()
		if err := level.UnmarshalText([]byte(cfg.Level)); err != nil {
			level.SetLevel(zap.InfoLevel)
		}

		consoleEncoder := getEncoder(cfg)
		consoleCore := zapcore.NewCore(consoleEncoder, zapcore.Lock(os.Stdout), level)
		cores := []zapcore.Core{consoleCore}

		if cfg.LogFile != "" {
			// File encoder is always JSON for structured logging.
			fileEncoder := getEncoder(config.LoggerConfig{Format: "json"})
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

// Custom level encoder that pulls from our config.
func customColorLevelEncoder(level zapcore.Level, enc zapcore.Encoder, colorConfig config.ColorConfig) {
	var color string
	levelStr := strings.ToUpper(level.String())

	// Grab the right color from the config map.
	switch level {
	case zapcore.DebugLevel:
		color = colorMap[colorConfig.Debug]
	case zapcore.InfoLevel:
		color = colorMap[colorConfig.Info]
	case zapcore.WarnLevel:
		color = colorMap[colorConfig.Warn]
	case zapcore.ErrorLevel:
		color = colorMap[colorConfig.Error]
	case zapcore.DPanicLevel:
		color = colorMap[colorConfig.DPanic]
	case zapcore.PanicLevel:
		color = colorMap[colorConfig.Panic]
	case zapcore.FatalLevel:
		color = colorMap[colorConfig.Fatal]
	default:
		// Fallback for any other levels.
		color = colorReset
	}

	// If a color was found, wrap the level string in ANSI codes.
	if color != "" {
		enc.AppendString(fmt.Sprintf("%s%s%s", color, levelStr, colorReset))
	} else {
		enc.AppendString(levelStr)
	}
}

func getEncoder(cfg config.LoggerConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder // This is the default.

	if cfg.Format == "console" {
		// If we're in console mode, we override the level encoder.
		encoderConfig.EncodeLevel = func(level zapcore.Level, enc zapcore.Encoder) {
			// This little closure passes our color config to the real encoder function.
			customColorLevelEncoder(level, enc, cfg.Colors)
		}
		return zapcore.NewConsoleEncoder(encoderConfig)
	}
	// For JSON format, we don't want color codes.
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
