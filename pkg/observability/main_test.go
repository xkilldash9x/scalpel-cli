// File: internal/observability/main_test.go
package observability_test

import (
	"os"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/pkg/observability"
	"go.uber.org/zap/zapcore"
)

// TestMain serves as the entry point for all tests in the observability package.
// It instantiates the global dependency-injected logger before running tests.
// Note: Individual tests (like TestInitializeLogger) may ResetForTest() and
// re-initialize the logger to verify specific behaviors.
func TestMain(m *testing.M) {
	// 1. Load default configuration.
	appConfig := config.NewDefaultConfig()
	logConfig := appConfig.Logger()

	// 2. Override settings for the test environment.
	logConfig.Level = "debug"
	logConfig.ServiceName = "test-suite"
	logConfig.Format = "console"

	// 3. Initialize the global logger.
	observability.Initialize(logConfig, zapcore.Lock(os.Stdout))

	// 4. Run the tests.
	exitCode := m.Run()

	// 5. Teardown and Sync.
	observability.Sync()

	// Explicitly reset the global state to be clean.
	observability.ResetForTest()

	// 6. Exit with the result code.
	os.Exit(exitCode)
}
