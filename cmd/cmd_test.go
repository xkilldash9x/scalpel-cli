// File: cmd/cmd_test.go
package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// TestConfigFlagOverride verifies that CLI flags correctly override configuration
// file settings and defaults.
func TestConfigFlagOverride(t *testing.T) {
	// Initialize logger for the test run to avoid noise.
	observability.ResetForTest()
	observability.InitializeLogger(config.LoggerConfig{Level: "fatal"})

	// FIX: Use the accurate newPristineRootCmd instead of the previously flawed helper.
	testRootCmd := newPristineRootCmd()

	configContent := `
discovery:
  max_depth: 5
browser:
  humanoid:
    enabled: false # Override the default of true
`
	configFile := createTempConfig(t, configContent)
	defer os.Remove(configFile)

	// Set required env var for the PersistentPreRunE validation (if needed by config).
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://user:pass@localhost/db")
	t.Setenv("GEMINI_API_KEY", "fake-key") // Ensure LLM validation passes

	// Find the scan command from our test rootCmd instance.
	scanCmd, _, err := testRootCmd.Find([]string{"scan"})
	require.NoError(t, err)
	require.NotNil(t, scanCmd)

	// We need to capture the configuration *after* the overrides are applied
	// in the scan command's logic.
	var capturedConfig config.Interface

	// Intercept the RunE function.
	// We must replicate the initial steps of the real RunE (from cmd/scan.go)
	// to ensure the configuration is correctly loaded from context and overrides are applied.
	scanCmd.RunE = func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()

		// 1. Get config from context (loaded by PersistentPreRunE)
		cfg, err := getConfigFromContext(ctx)
		if err != nil {
			return err
		}

		// 2. Apply flag overrides (the logic we want to test)
		applyScanFlagOverrides(cmd, cfg)

		// 3. Capture the final state of the configuration
		capturedConfig = cfg

		// 4. Stop execution (we don't want to run the actual scan/runScan)
		return nil
	}

	// Execute the command.
	// PersistentPreRunE will load the config file.
	// The intercepted RunE will apply the --depth flag.
	testRootCmd.SetArgs([]string{"--config", configFile, "scan", "--depth", "2", "http://target.com"})
	err = testRootCmd.ExecuteContext(context.Background())
	require.NoError(t, err, "Command execution should not produce an error")

	// Assert against the captured configuration.
	require.NotNil(t, capturedConfig)

	// Assert that the flag (--depth 2) overrode the file (max_depth: 5).
	assert.Equal(t, 2, capturedConfig.Discovery().MaxDepth, "Discovery depth should be overridden by the --depth flag")

	// Assert that the file setting (humanoid: false) overrode the default (true).
	assert.False(t, capturedConfig.Browser().Humanoid.Enabled, "Humanoid enabled should be false from the YAML file")
}

func TestScanCmd_RequiredArgs(t *testing.T) {
	output, err := executeCommandNoPreRun(t, "scan")
	require.Error(t, err)
	// Check for the standard Cobra error message for missing arguments.
	assert.Contains(t, output, "Error: requires at least 1 arg(s), only received 0")
}

func TestReportCmd_RequiredFlags(t *testing.T) {
	output, err := executeCommandNoPreRun(t, "report")
	require.Error(t, err)
	assert.Contains(t, output, "Error: required flag(s) \"scan-id\" not set")
}

// TestScanCommand_Logic is an example of a test for the command's business logic,
// where using newTestConfig is appropriate.
func TestScanCommand_Logic(t *testing.T) {
	// 1. Use the helper to get a valid config object.
	cfg := newTestConfig(t)

	// This is where you would test the actual work of the scan command.
	// You might pass the `cfg` object to a scanner service.
	// For example:
	// scannerService := scanner.New(cfg)
	// results, err := scannerService.Run("http://example.com")
	// assert.NoError(t, err)
	// assert.NotEmpty(t, results)

	// This is just a placeholder assertion to make the test pass.
	require.NotNil(t, cfg)
	assert.Equal(t, "postgres", cfg.Agent().KnowledgeGraph.Type)
}
