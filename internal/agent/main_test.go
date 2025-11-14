package agent

import (
	"os"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// TestMain is executed before any tests in this package.
func TestMain(m *testing.M) {
	// Initialize a simple logger for testing purposes to avoid spamming the console.
	// This prevents the "Global logger requested before initialization" warning.
	cfg := config.NewDefaultConfig().Logger()
	cfg.Level = "fatal" // Silence all logs except fatal during tests
	observability.InitializeLogger(cfg)

	// After running all tests, ensure logs are flushed.
	defer observability.Sync()

	os.Exit(m.Run())
}
