// File: internal/observability/logger_test.go
package observability

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// -- Test Helper Functions --

// setupTestLogger initializes the global logger to write to a buffer for testing.
func setupTestLogger(cfg config.LoggerConfig) *bytes.Buffer {
	buf := new(bytes.Buffer)
	// Wrap the buffer in a WriteSyncer.
	writer := zapcore.AddSync(buf)
	// Call the exported initializer, directing console output to the buffer.
	Initialize(cfg, writer)
	return buf
}

// -- Test Cases --

func TestInitializeLogger(t *testing.T) {

	t.Run("should initialize console logger with colors", func(t *testing.T) {
		// Use the exported reset function to ensure a clean slate.
		ResetForTest()

		cfg := config.LoggerConfig{
			Level:       "debug",
			Format:      "console",
			ServiceName: "TestService",
			Colors: config.ColorConfig{ // -- testing our color configuration --
				Info: "green",
			},
		}

		buf := setupTestLogger(cfg)

		logger := GetLogger()
		logger.Info("This is a test message.")
		Sync() // -- ensure the log is flushed --

		output := buf.String()
		assert.Contains(t, output, "INFO", "Output should contain the log level")
		assert.Contains(t, output, "This is a test message.", "Output should contain the message")
		assert.Contains(t, output, colorGreen, "Info level should be colorized green")
		assert.Contains(t, output, colorReset, "Output should contain the reset color code")
	})

	t.Run("should initialize json logger", func(t *testing.T) {
		ResetForTest()

		cfg := config.LoggerConfig{
			Level:       "info",
			Format:      "json",
			ServiceName: "JSONTest",
		}

		buf := setupTestLogger(cfg)

		logger := GetLogger()
		logger.Warn("This is a JSON message.", zap.String("key", "value"))
		Sync()

		// -- the output should be a valid JSON object --
		var logEntry map[string]interface{}
		err := json.Unmarshal(buf.Bytes(), &logEntry)
		require.NoError(t, err, "Log output should be valid JSON")

		assert.Equal(t, "WARN", logEntry["level"])
		assert.Equal(t, "JSONTest", logEntry["logger"])
		assert.Equal(t, "This is a JSON message.", logEntry["msg"])
		assert.Equal(t, "value", logEntry["key"])
	})

	t.Run("should write to a log file if configured", func(t *testing.T) {
		ResetForTest()
		// -- create a temporary file for the log output --
		tmpFile, err := os.CreateTemp("", "logger-test-*.log")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		cfg := config.LoggerConfig{
			Level:   "debug",
			Format:  "json",
			LogFile: tmpFile.Name(),
			MaxSize: 1, // 1 MB
		}
		// We call Initialize directly to avoid writing to the console.
		Initialize(cfg, zapcore.AddSync(io.Discard))
		logger := GetLogger()
		logger.Error("This should go to the file.")
		Sync()

		content, err := os.ReadFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Contains(t, string(content), "This should go to the file.", "Log file should contain the message")
	})

	t.Run("should only initialize once", func(t *testing.T) {
		ResetForTest()

		// -- first initialization --
		// Use console format for easier string comparison of the service name.
		cfg1 := config.LoggerConfig{Level: "info", Format: "console", ServiceName: "First"}
		buf1 := setupTestLogger(cfg1)
		logger1 := GetLogger()

		// -- second, should be ignored due to sync.Once --
		cfg2 := config.LoggerConfig{Level: "debug", Format: "console", ServiceName: "Second"}
		// This initialization is ignored, but we still get a buffer back.
		buf2 := setupTestLogger(cfg2)
		logger2 := GetLogger()

		// -- check that the logger is the same instance with the first config --
		assert.Equal(t, logger1, logger2)
		logger2.Info("test message") // This log will be written to buf1.
		Sync()

		// The service name should be "First", not "Second".
		output := buf1.String()
		assert.Contains(t, output, "First")
		assert.Contains(t, output, "test message")
		assert.NotContains(t, output, "Second")
		// Ensure the second buffer remains empty because the second initialization was a no-op.
		assert.Empty(t, buf2.String())
	})
}

func TestGetLogger(t *testing.T) {
	t.Run("should return a fallback logger if not initialized", func(t *testing.T) {
		ResetForTest()

		// Capture stderr to prevent the fallback warning from polluting test output.
		oldStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w

		// -- we do not call InitializeLogger() here --
		logger := GetLogger()
		require.NotNil(t, logger)

		// Close the writer and restore stderr.
		w.Close()
		os.Stderr = oldStderr

		// Read the captured output.
		var buf bytes.Buffer
		io.Copy(&buf, r)

		// Assert that the warning was logged.
		assert.Contains(t, buf.String(), "Global logger requested before initialization")
	})

	t.Run("should return the global logger after initialization", func(t *testing.T) {
		ResetForTest()
		cfg := config.LoggerConfig{Level: "info", ServiceName: "GlobalTest"}
		InitializeLogger(cfg)

		logger := GetLogger()
		// The pointer to the logger instance should be the same as the one stored.
		assert.Equal(t, globalLogger.Load(), logger)
	})
}
