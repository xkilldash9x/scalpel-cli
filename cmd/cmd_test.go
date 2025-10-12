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
)

// executeCommandNoPreRun is for testing argument and flag validation without
// triggering the config validation in PersistentPreRunE.
func executeCommandNoPreRun(t *testing.T, args ...string) (string, error) {
	t.Helper()
	// Create a new root command for each test run to ensure isolation.
	testRootCmd, _ := newRootCmd()

	buf := new(bytes.Buffer)
	testRootCmd.PersistentPreRunE = nil // Disable config loading for simple validation tests.
	testRootCmd.SetOut(buf)
	testRootCmd.SetErr(buf)
	testRootCmd.SetArgs(args)
	err := testRootCmd.ExecuteContext(context.Background())
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
		// We will perform assertions on the captured config pointers after execution.
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
	assert.Equal(t, 2, appCfg.Scan().Depth)
	assert.Equal(t, 2, appCfg.Discovery().MaxDepth)

	// Assert against the nested humanoid config.
	// Value from YAML should override the default.
	assert.False(t, appCfg.Browser().Humanoid.Enabled)
}

func TestScanCmd_RequiredArgs(t *testing.T) {
	output, err := executeCommandNoPreRun(t, "scan")
	require.Error(t, err)
	assert.Contains(t, output, "Error: requires at least 1 arg(s), only received 0")
}

func TestReportCmd_RequiredFlags(t *testing.T) {
	output, err := executeCommandNoPreRun(t, "report")
	require.Error(t, err)
	assert.Contains(t, output, "Error: required flag(s) \"scan-id\" not set")
}

// newRootCmd is a helper to create a clean rootCmd instance for testing,
// returning the command and a pointer to its config variable.
func newRootCmd() (*cobra.Command, *config.Interface) {
	var cfgFile string
	var appConfig config.Interface

	rootCmd := &cobra.Command{
		Use:   "scalpel-cli",
		Short: "A powerful security tool for web application analysis.",
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			v := viper.New()
			config.SetDefaults(v) // Set defaults before reading config

			if cfgFile != "" {
				v.SetConfigFile(cfgFile)
			} else {
				v.AddConfigPath(".")
				v.SetConfigName("scalpel")
			}
			v.AutomaticEnv()

			if err := v.ReadInConfig(); err != nil {
				if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
					return err
				}
			}

			// Bind flags after setting defaults and reading config, but before unmarshaling.
			if cmd.Flags().Changed("depth") {
				v.Set("discovery.max_depth", v.GetInt("scan.depth"))
			}

			// config.NewConfigFromViper returns a concrete type, but we store it in our interface variable.
			concreteCfg, err := config.NewConfigFromViper(v)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}
			appConfig = concreteCfg

			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./scalpel.yaml)")

	// Add subcommands to this test rootCmd
	scanCmd := &cobra.Command{
		Use:  "scan [targets...]",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// In a real app, you would now use appConfig to initialize and run your scanner service.
			return nil
		},
	}
	scanCmd.Flags().IntP("depth", "d", 0, "Crawling depth limit")
	viper.BindPFlag("scan.depth", scanCmd.Flags().Lookup("depth"))

	rootCmd.AddCommand(scanCmd)

	reportCmd := &cobra.Command{
		Use:  "report",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	reportCmd.Flags().String("scan-id", "", "Scan ID to generate a report for")
	reportCmd.MarkFlagRequired("scan-id")
	rootCmd.AddCommand(reportCmd)

	return rootCmd, &appConfig
}
