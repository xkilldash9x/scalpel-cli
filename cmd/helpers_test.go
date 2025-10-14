// File: cmd/helpers_test.go
package cmd

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
)

// newTestConfig creates a fully populated and layered configuration for use in tests.
// It correctly layers defaults, explicit values, and environment variables.
func newTestConfig(t *testing.T) config.Interface {
	t.Helper()

	// 1. Create a single Viper instance that will hold all config layers.
	v := viper.New()

	// 2. Set all the default values from your config package. This is the base layer.
	config.SetDefaults(v)

	// 3. Set any explicit values for the test environment.
	v.Set("browser.debug", true)
	v.Set("autofix.git.author_name", "Kyle McAllister")
	v.Set("autofix.git.author_email", "xkilldash9x@proton.me")
	v.Set("autofix.github.repo_owner", "xkilldash9x")
	v.Set("autofix.github.repo_name", "scalpel-cli")
	v.Set("network.headers.User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 ScalpelV2/1.0")

	// 4. Set environment variables that the test will use.
	t.Setenv("SCALPEL_DATABASE_URL", "postgres://test:test@localhost/testdb")
	t.Setenv("SCALPEL_AGENT_LLM_MODELS_GEMINI-2.5-PRO_API_KEY", "fake-api-key-for-testing")

	// 5. Configure Viper to automatically read environment variables.
	v.SetEnvPrefix("SCALPEL")
	v.AutomaticEnv()

	// 6. Create the final config object from the layered Viper instance.
	cfg, err := config.NewConfigFromViper(v)
	require.NoError(t, err, "Failed to create new test config from viper")

	return cfg
}

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
	require.NoError(t, tmpfile.Close())
	return tmpfile.Name()
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

			// The logic here now perfectly mirrors the application's `initializeConfig`
			// This is the key to fixing the test failures.

			// 1. Set default values.
			config.SetDefaults(v)

			// 2. Set up environment variable handling.
			v.SetEnvPrefix("SCALPEL")
			v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
			v.AutomaticEnv()

			// 3. Bind cobra flags to our local Viper instance.
			if err := v.BindPFlags(cmd.Flags()); err != nil {
				return fmt.Errorf("failed to bind command flags: %w", err)
			}
			if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
				return fmt.Errorf("failed to bind persistent command flags: %w", err)
			}

			// 4. Read the configuration file if specified.
			if cfgFile != "" {
				v.SetConfigFile(cfgFile)
				if err := v.ReadInConfig(); err != nil {
					if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
						return fmt.Errorf("error reading config file: %w", err)
					}
				}
			}

			// 5. Create the final config object from the layered Viper instance.
			concreteCfg, err := config.NewConfigFromViper(v)
			if err != nil {
				return fmt.Errorf("failed to load or validate config: %w", err)
			}
			appConfig = concreteCfg

			// 6. Manually apply the command-specific logic that normally happens in RunE.
			// This is necessary because tests often mock the RunE function.
			if cmd.Use == "scan [targets...]" {
				// FIX: Read the depth value directly from the Cobra flag.
				depth, _ := cmd.Flags().GetInt("depth")

				if cmd.Flags().Changed("depth") {
					// depth, _ := cmd.Flags().GetInt("depth") // Moved up
					appConfig.SetDiscoveryMaxDepth(depth)
				}
				scanCfg := appConfig.Scan()
				// scanCfg.Depth = v.GetInt("scan.depth") // Old logic relied on incorrect Viper binding
				scanCfg.Depth = depth // Use the depth read from the flag
				scanCfg.Targets = args
				appConfig.SetScanConfig(scanCfg)
			}
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is ./scalpel.yaml)")

	// --- Add subcommands ---
	scanCmd := &cobra.Command{
		Use:  "scan [targets...]",
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return nil
		},
	}
	scanCmd.Flags().IntP("depth", "d", 0, "Crawling depth limit")
	// FIX: Removed the binding to the global viper instance, which caused confusion and test failures.
	// _ = viper.BindPFlag("scan.depth", scanCmd.Flags().Lookup("depth"))

	rootCmd.AddCommand(scanCmd)

	reportCmd := &cobra.Command{
		Use:  "report",
		RunE: func(cmd *cobra.Command, args []string) error { return nil },
	}
	reportCmd.Flags().String("scan-id", "", "Scan ID to generate a report for")
	_ = reportCmd.MarkFlagRequired("scan-id")
	rootCmd.AddCommand(reportCmd)

	return rootCmd, &appConfig
}
