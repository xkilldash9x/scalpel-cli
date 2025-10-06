// File: cmd/cmd_test.go
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// Helper function to reset Viper and the command structure before each test.
func resetCmd(t *testing.T) {
	t.Helper()
	viper.Reset()
	cfgFile = ""
	// Reset the global config instance to an empty one.
	config.Set(&config.Config{})
	// Reset logger to a silent state
	observability.InitializeLogger(config.LoggerConfig{Level: "fatal", Format: "console", ServiceName: "test"})

	// Re-initialize the root command structure.
	persistentPreRunE := rootCmd.PersistentPreRunE
	rootCmd = &cobra.Command{
		Use:               "scalpel-cli",
		Short:             "Scalpel is an AI-native security scanner.",
		Version:           Version,
		PersistentPreRunE: persistentPreRunE,
	}
	// Re-attach flags and subcommands
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
	rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newReportCmd())
}

// executeCommand simulates running the CLI command.
func executeCommand(t *testing.T, args ...string) (output string, err error) {
	t.Helper()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs(args)

	// Use a background context for execution
	ctx := context.Background()
	err = rootCmd.ExecuteContext(ctx)

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

func TestInitializeConfig_GeminiEnvVariables(t *testing.T) {
	resetCmd(t)
	t.Setenv("SCALPEL_GEMINI_API_KEY", "short-key-123")
	err := initializeConfig()
	require.NoError(t, err)
	assert.Equal(t, "short-key-123", viper.GetString("agent.llm.gemini_api_key"))

	resetCmd(t)
	t.Setenv("SCALPEL_AGENT_LLM_GEMINI_API_KEY", "structured-key-456")
	err = initializeConfig()
	require.NoError(t, err)
	assert.Equal(t, "structured-key-456", viper.GetString("agent.llm.gemini_api_key"))
}

func TestInitializeConfig_EnvOverrideFile(t *testing.T) {
	resetCmd(t)
	configContent := `
database:
  url: "file://config-db-url"
agent:
  llm:
    gemini_api_key: "file-gemini-key"
`
	configFile := createTempConfig(t, configContent)
	defer os.Remove(configFile)

	t.Setenv("SCALPEL_DATABASE_URL", "env://override-db-url")
	t.Setenv("SCALPEL_GEMINI_API_KEY", "env-override-key")
	cfgFile = configFile
	err := initializeConfig()
	require.NoError(t, err)
	assert.Equal(t, "env://override-db-url", viper.GetString("database.url"))
	assert.Equal(t, "env-override-key", viper.GetString("agent.llm.gemini_api_key"))
}

// TestConfigFlagOverride verifies that CLI flags override configuration (File and ENV).
func TestConfigFlagOverride(t *testing.T) {
	resetCmd(t)

	// 1. Setup Config File
	configContent := `
browser:
  concurrency: 5
discovery:
  max_depth: 5
engine:
  worker_concurrency: 10
`
	configFile := createTempConfig(t, configContent)
	defer os.Remove(configFile)

	// 2. Setup ENV Variables
	t.Setenv("SCALPEL_ENGINE_WORKER_CONCURRENCY", "15")
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://user:pass@localhost/db")

	scanCmd, _, err := rootCmd.Find([]string{"scan"})
	require.NoError(t, err)

	var capturedConfig *config.Config

	// Intercept the RunE function to capture the config state *after* flags are processed.
	originalRunE := scanCmd.RunE
	scanCmd.RunE = func(cmd *cobra.Command, args []string) error {
		// This is the critical part: we must replicate the config finalization logic
		// from the actual scan command's RunE.
		if err := viper.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("failed to bind command flags: %w", err)
		}
		cfg := config.Get()
		if err := viper.Unmarshal(cfg); err != nil {
			return fmt.Errorf("failed to re-unmarshal config with flag overrides: %w", err)
		}

		capturedConfig = cfg
		return assert.AnError // Stop execution after capturing the config.
	}
	defer func() { scanCmd.RunE = originalRunE }() // Restore the original function after the test.

	// 3. Execute the command
	args := []string{"--config", configFile, "scan", "--depth", "2", "-j", "20", "http://target.com"}
	_, err = executeCommand(t, args...)

	// We expect the specific error we returned from our interceptor.
	require.ErrorIs(t, err, assert.AnError, "The intercepted RunE should return a known error")
	require.NotNil(t, capturedConfig)

	// Assert that the flag values correctly overrode the config file and environment variables.
	assert.Equal(t, 2, capturedConfig.Discovery.MaxDepth, "Depth flag should override config")
	assert.Equal(t, 20, capturedConfig.Engine.WorkerConcurrency, "Concurrency flag should override config and env")
	assert.Equal(t, 5, capturedConfig.Browser.Concurrency, "Browser concurrency should be loaded from the config file")
}

func TestScanCmd_RequiredArgs(t *testing.T) {
	resetCmd(t)
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")
	output, err := executeCommand(t, "scan")
	require.Error(t, err)
	assert.Contains(t, output, "Error: requires at least 1 arg(s), only received 0")
}

func TestReportCmd_RequiredFlags(t *testing.T) {
	resetCmd(t)
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")
	output, err := executeCommand(t, "report")
	require.Error(t, err)
	assert.Contains(t, output, "Error: required flag(s) \"scan-id\" not set")
}