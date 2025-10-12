// File: cmd/main_test.go
package cmd

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

// resetForTest provides the single source of truth for resetting test state.
func resetForTest(t *testing.T) {
	t.Helper()

	// 1. Reset Viper and prevent auto-discovery
	viper.Reset()
	viper.SetConfigName("a-config-file-that-does-not-exist")

	// 2. Reset package-level variables from root.go
	cfgFile = ""
	validateFix = false
	osExit = os.Exit

	// 3. Reset the logger to a silent state
	// NOTE: The global config singleton is gone, so no need to reset it.
	observability.InitializeLogger(config.LoggerConfig{Level: "fatal", Format: "console", ServiceName: "test"})

	// 4. Re-initialize the root command to its pristine state
	// This prevents state leakage within Cobra itself.
	rootCmd = newPristineRootCmd()
}

// newPristineRootCmd is a helper to get a pristine version of the root command for integration tests.
// RENAMED from newRootCmd to avoid collision with the helper in cmd_test.go
func newPristineRootCmd() *cobra.Command {
	// This function body is a copy of the `rootCmd` var initialization in `root.go`
	cmd := &cobra.Command{
		Use:     "scalpel-cli",
		Short:   "Scalpel is an AI-native security scanner.",
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// This logic should mirror the new, non-singleton approach in cmd/root.go

			v := viper.New()
			config.SetDefaults(v)

			// 1. Initialize configuration loading
			if err := initializeConfig(cmd, v); err != nil {
				// Initialize a basic logger if config loading fails early.
				basicLogger, _ := zap.NewDevelopment()
				defer basicLogger.Sync()
				basicLogger.Error("Failed to initialize configuration", zap.Error(err))
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}

			// 2. Create the configuration object from viper.
			// The config object is now self-contained and not stored in a global singleton.
			cfg, err := config.NewConfigFromViper(v)
			if err != nil {
				observability.InitializeLogger(config.LoggerConfig{Level: "info", Format: "console", ServiceName: "scalpel-cli"})
				return fmt.Errorf("failed to load or validate config: %w", err)
			}

			// 3. Initialize the logger with the loaded config.
			// CORRECTED: Called cfg.Logger() as a method.
			observability.InitializeLogger(cfg.Logger())
			logger := observability.GetLogger()
			logger.Info("Starting Scalpel-CLI", zap.String("version", Version))

			// 4. Store the validated config in the command's context for subcommands.
			// ADDED: This is crucial for tests of subcommands to work correctly.
			ctx := context.WithValue(cmd.Context(), configKey, cfg)
			cmd.SetContext(ctx)

			// Handle the validation run flag
			if validateFix {
				cmd.Println("===[ VALIDATION RUN PASSED ]===")
				osExit(0)
			}
			return nil
		},
	}
	// Manually re-run the logic from the original init() and Execute() functions
	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
	cmd.PersistentFlags().BoolVar(&validateFix, "validate-fix", false, "Internal flag for self-healing validation.")
	_ = cmd.PersistentFlags().MarkHidden("validate-fix")

	// Re-attach subcommands
	cmd.AddCommand(newScanCmd())
	cmd.AddCommand(newReportCmd())
	cmd.AddCommand(newSelfHealCmd())
	cmd.AddCommand(newEvolveCmd())
	return cmd
}
