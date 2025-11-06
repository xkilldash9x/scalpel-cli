// File: internal/observability/logger.go
package observability

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"net/http"
	"time"

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

// NewLogger initializes the logger based on configuration and returns the instance.
// It sets up the global logger state but also returns the logger for direct use (dependency injection).
func NewLogger(cfg config.LoggerConfig) (*zap.Logger, error) {
	// Use the standard console writer (locked Stdout) for initialization.
	Initialize(cfg, zapcore.Lock(os.Stdout))

	// Retrieve the initialized logger.
	logger := GetLogger()

	// Basic validation
	if logger == nil || logger.Core() == zapcore.NewNopCore() {
		return nil, fmt.Errorf("logger initialization failed unexpectedly")
	}

	return logger, nil
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
// Deprecated: Prefer NewLogger for dependency injection.
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

func getEncoder(cfg config.LoggerConfig) zapcore.Encoder {
	encoderConfig := zap.NewProductionEncoderConfig()
	encoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

	if cfg.Format == "console" {
		encoderConfig.EncodeLevel = newColorizedLevelEncoder(cfg.Colors)
		return zapcore.NewConsoleEncoder(encoderConfig)
	}

	// JSON format defaults.
	encoderConfig.EncodeLevel = zapcore.CapitalLevelEncoder
	return zapcore.NewJSONEncoder(encoderConfig)
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
		l = l.Named("fallback")
		// Log a warning that the fallback is being used.
		l.Warn("Global logger requested before initialization; using fallback.")

		// Attempt to store the fallback logger atomically if it's still nil.
		if globalLogger.CompareAndSwap(nil, l) {
			return l
		}
		// If another thread initialized it concurrently, return the initialized one.
		return globalLogger.Load()
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
			// Check for common errors related to closed pipes or invalid arguments during shutdown.
			if !strings.Contains(errMsg, "sync /dev/stdout") &&
				!strings.Contains(errMsg, "sync /dev/stderr") &&
				!strings.Contains(errMsg, "invalid argument") &&
				!strings.Contains(errMsg, "operation not supported") &&
				!strings.Contains(errMsg, "write: broken pipe") {
				fmt.Fprintln(os.Stderr, "Error: failed to sync logger:", err)
			}
		}
	}
}

// ZapLogger is a chi middleware that logs requests using Zap.
func ZapLogger(logger *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Create a logger specific to this request, adding request details.
			reqLogger := logger.With(
				zap.String("method", r.Method),
				zap.String("url", r.URL.String()),
				zap.String("remote_addr", r.RemoteAddr),
				zap.String("user_agent", r.UserAgent()),
			)

			// Use a custom response writer to capture status code.
			ww := &loggingResponseWriter{ResponseWriter: w, statusCode: http.StatusOK}

			start := time.Now()
			defer func() {
				// Log the request completion.
				reqLogger.Info("Request completed",
					zap.Int("status", ww.statusCode),
					zap.Duration("duration", time.Since(start)),
				)
			}()

			// Serve the request.
			next.ServeHTTP(ww, r)
		})
	}
}

// loggingResponseWriter captures the status code written to the header.
type loggingResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

// WriteHeader captures the status code and calls the original WriteHeader.
func (lrw *loggingResponseWriter) WriteHeader(statusCode int) {
	lrw.statusCode = statusCode
	lrw.ResponseWriter.WriteHeader(statusCode)
}

// Write calls the original Write, ensuring WriteHeader is called if it hasn't been.
func (lrw *loggingResponseWriter) Write(b []byte) (int, error) {
	// If WriteHeader has not been called, the default status is http.StatusOK.
	// We don't need to do anything special here, as the status code is
	// already set to OK by default or captured by WriteHeader.
	return lrw.ResponseWriter.Write(b)
}
