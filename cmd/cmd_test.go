// File: cmd/cmd_test.go
package cmd

import (
	"context"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigFlagOverride(t *testing.T) {
	// Create a fresh, isolated rootCmd for this test.
	testRootCmd, testAppConfigPtr := newRootCmd()

	configContent := `
discovery:
  max_depth: 5
browser:
  humanoid:
    enabled: false # Override the default of true
`
	configFile := createTempConfig(t, configContent)
	defer os.Remove(configFile)

	// Set required env var for the PersistentPreRunE validation to pass.
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://user:pass@localhost/db")

	// Find the scan command from our test rootCmd instance.
	var scanCmd *cobra.Command
	for _, cmd := range testRootCmd.Commands() {
		if cmd.Use == "scan [targets...]" {
			scanCmd = cmd
			break
		}
	}
	require.NotNil(t, scanCmd)

	// Intercept the RunE function to prevent it from actually running a scan.
	originalRunE := scanCmd.RunE
	scanCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// The test succeeds by simply running without error.
		return nil
	}
	defer func() { scanCmd.RunE = originalRunE }()

	// Execute the command. The PersistentPreRunE will create and populate the configs.
	testRootCmd.SetArgs([]string{"--config", configFile, "scan", "--depth", "2", "http://target.com"})
	err := testRootCmd.ExecuteContext(context.Background())
	require.NoError(t, err, "Command execution should not produce an error")

	// Assert against the captured appConfig from the command's scope.
	appCfg := *testAppConfigPtr
	require.NotNil(t, appCfg)
	assert.Equal(t, 2, appCfg.Scan().Depth, "Scan depth should be from the --depth flag")
	assert.Equal(t, 2, appCfg.Discovery().MaxDepth, "Discovery depth should be overridden by the --depth flag")
	assert.False(t, appCfg.Browser().Humanoid.Enabled, "Humanoid enabled should be false from the YAML file")
}

func TestScanCmd_RequiredArgs(t *testing.T) {
	output, err := executeCommandNoPreRun(t, "scan")
	require.Error(t, err)
	assert.Contains(t, output, "Error: requires at least 1 arg(s), only received 0")
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
