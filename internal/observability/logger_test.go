// internal/observability/logger_test.go
package observability

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"go.uber.org/zap"
)

// -- Test Helper Functions --

// captureOutput is a helper function to capture stdout for the duration of a test.
// It returns a function to be called with defer to restore the original stdout.
func captureOutput(t *testing.T) (*bytes.Buffer, func()) {
	t.Helper()
	originalStdout := os.Stdout
	r, w, err := os.Pipe()
	require.NoError(t, err)

	os.Stdout = w
	var buf bytes.Buffer
	go func() {
		_, _ = buf.ReadFrom(r)
	}()

	// The cleanup function restores stdout and closes the pipe writer.
	cleanup := func() {
		w.Close()
		os.Stdout = originalStdout
	}
	return &buf, cleanup
}

// resetGlobalLogger is critical for ensuring test isolation, as the logger
// is a global singleton. We must reset it before each test.
func resetGlobalLogger() {
	// Reset the sync.Once so InitializeLogger can be called again.
	once = sync.Once{}
	// Set the atomic pointer to nil.
	globalLogger.Store(nil)
}

// -- Test Cases --

func TestInitializeLogger(t *testing.T) {

	t.Run("should initialize console logger with colors", func(t *testing.T) {
		resetGlobalLogger()
		buf, cleanup := captureOutput(t)
		defer cleanup()

		cfg := config.LoggerConfig{
			Level:       "debug",
			Format:      "console",
			ServiceName: "TestService",
			Colors: config.ColorConfig{ // -- testing our color configuration --
				Info: "green",
			},
		}
		InitializeLogger(cfg)
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
		resetGlobalLogger()
		buf, cleanup := captureOutput(t)
		defer cleanup()

		cfg := config.LoggerConfig{
			Level:       "info",
			Format:      "json",
			ServiceName: "JSONTest",
		}
		InitializeLogger(cfg)
		logger := GetLogger()
		logger.Warn("This is a JSON message.", zap.String("key", "value"))
		Sync()

		// -- the output should be a valid JSON object --
		var logEntry map[string]interface{}
		err := json.Unmarshal(buf.Bytes(), &logEntry)
		require.NoError(t, err, "Log output should be valid JSON")

		assert.Equal(t, "warn", logEntry["level"])
		assert.Equal(t, "JSONTest", logEntry["logger"])
		assert.Equal(t, "This is a JSON message.", logEntry["msg"])
		assert.Equal(t, "value", logEntry["key"])
	})

	t.Run("should write to a log file if configured", func(t *testing.T) {
		resetGlobalLogger()
		// -- create a temporary file for the log output --
		tmpFile, err := ioutil.TempFile("", "logger-test-*.log")
		require.NoError(t, err)
		defer os.Remove(tmpFile.Name())

		cfg := config.LoggerConfig{
			Level:   "debug",
			Format:  "json",
			LogFile: tmpFile.Name(),
			MaxSize: 1, // 1 MB
		}
		InitializeLogger(cfg)
		logger := GetLogger()
		logger.Error("This should go to the file.")
		Sync()

		content, err := ioutil.ReadFile(tmpFile.Name())
		require.NoError(t, err)
		assert.Contains(t, string(content), "This should go to the file.", "Log file should contain the message")
	})

	t.Run("should only initialize once", func(t *testing.T) {
		resetGlobalLogger()
		buf, cleanup := captureOutput(t)
		defer cleanup()

		// -- first initialization --
		cfg1 := config.LoggerConfig{Level: "info", ServiceName: "First"}
		InitializeLogger(cfg1)
		logger1 := GetLogger()

		// -- second, should be ignored --
		cfg2 := config.LoggerConfig{Level: "debug", ServiceName: "Second"}
		InitializeLogger(cfg2)
		logger2 := GetLogger()

		// -- check that the logger is the same instance with the first config --
		assert.Equal(t, logger1, logger2)
		logger2.Info("test")
		Sync()

		// The service name should be "First", not "Second"
		assert.True(t, strings.Contains(buf.String(), "First"))
		assert.False(t, strings.Contains(buf.String(), "Second"))
	})
}

func TestGetLogger(t *testing.T) {
	t.Run("should return a fallback logger if not initialized", func(t *testing.T) {
		resetGlobalLogger()
		// -- we do not call InitializeLogger() here --
		logger := GetLogger()
		require.NotNil(t, logger)

		// The fallback logger is a development logger named "fallback".
		// We can't easily assert its exact type, but we can check its behavior.
		// A non-nil check is a good indicator it worked.
	})

	t.Run("should return the global logger after initialization", func(t *testing.T) {
		resetGlobalLogger()
		cfg := config.LoggerConfig{Level: "info", ServiceName: "GlobalTest"}
		InitializeLogger(cfg)

		logger := GetLogger()
		// The pointer to the logger instance should be the same as the one stored.
		assert.Equal(t, globalLogger.Load(), logger)
	})
}
