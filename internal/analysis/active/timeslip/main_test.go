package timeslip

import (
	"os"
	"testing"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

func TestMain(m *testing.M) {
	// Initialize the logger for all tests in this package.
	observability.InitializeLogger(config.LoggerConfig{
		Level:  "debug",
		Format: "console",
	})
	// Run the tests.
	os.Exit(m.Run())
}
