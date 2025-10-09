// File: cmd/cmd_test.go
package cmd

import (
	"bytes"
	"context"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// executeCommandNoPreRun is for testing argument and flag validation without
// triggering the config validation in PersistentPreRunE.
func executeCommandNoPreRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// ALWAYS start with a reset to ensure no state leakage.
	resetForTest(t)

	buf := new(bytes.Buffer)
	// Use the global rootCmd that was reset.
	rootCmd.PersistentPreRunE = nil // Disable validation for this specific test type.
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)
	err := rootCmd.ExecuteContext(context.Background())
	return buf.String(), err
}

// createTempConfig helper
func createTempConfig(t *testing.T, content string) string {
	t.Helper()
	tmpfile, err := os.CreateTemp("", "test-config-*.yaml")
	require.NoError(t, err)
	_, err = tmpfile.Write([]byte(content))
	require.NoError(t, err)
	tmpfile.Close()
	return tmpfile.Name()
}

func TestConfigFlagOverride(t *testing.T) {
	// ALWAYS start with a reset.
	resetForTest(t)
	t.Cleanup(func() { resetForTest(t) })

	configContent := `
browser:
  concurrency: 5
discovery:
  max_depth: 5
`
	configFile := createTempConfig(t, configContent)
	defer os.Remove(configFile)

	// Set required env var BEFORE any command logic runs.
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://user:pass@localhost/db")

	var capturedConfig *config.Config

	// Find the scan command from our pristine, reset rootCmd.
	var scanCmd *cobra.Command
	for _, cmd := range rootCmd.Commands() {
		if cmd.Use == "scan [targets...]" {
			scanCmd = cmd
			break
		}
	}
	require.NotNil(t, scanCmd)

	// Intercept the RunE function.
	originalRunE := scanCmd.RunE
	scanCmd.RunE = func(cmd *cobra.Command, args []string) error {
		capturedConfig = config.Get()
		return assert.AnError
	}
	defer func() { scanCmd.RunE = originalRunE }()

	// Use the global rootCmd for execution.
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--config", configFile, "scan", "--depth", "2", "http://target.com"})

	err := rootCmd.ExecuteContext(context.Background())
	require.ErrorIs(t, err, assert.AnError, "The intercepted RunE should return a known error")

	require.NotNil(t, capturedConfig)
	assert.Equal(t, 2, capturedConfig.Discovery.MaxDepth, "Depth flag should override config")
}

func TestScanCmd_RequiredArgs(t *testing.T) {
	// No need to reset here because executeCommandNoPreRun does it.
	output, err := executeCommandNoPreRun(t, "scan")
	require.Error(t, err)
	assert.Contains(t, output, "Error: requires at least 1 arg(s), only received 0")
}

func TestReportCmd_RequiredFlags(t *testing.T) {
	// No need to reset here because executeCommandNoPreRun does it.
	output, err := executeCommandNoPreRun(t, "report")
	require.Error(t, err)
	assert.Contains(t, output, "Error: required flag(s) \"scan-id\" not set")
}
