// File: cmd/main_test.go
package cmd

import (
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
// It is the most robust version, combining all cleanup logic.
func resetForTest(t *testing.T) {
	t.Helper()

	// 1. Reset Viper and prevent auto-discovery
	viper.Reset()
	viper.SetConfigName("a-config-file-that-does-not-exist")

	// 2. Reset package-level variables from root.go
	cfgFile = ""
	validateFix = false
	osExit = os.Exit

	// 3. Reset the global config singleton
	config.Set(&config.Config{})

	// 4. Reset the logger to a silent state
	observability.InitializeLogger(config.LoggerConfig{Level: "fatal", Format: "console", ServiceName: "test"})

	// 5. Re-initialize the root command to its pristine state
	// This is the crucial step that prevents state leakage within Cobra itself.
	rootCmd = newRootCmd()
}

// newRootCmd is a helper to get a pristine version of the root command.
func newRootCmd() *cobra.Command {
	// This function body is a copy of the `rootCmd` var initialization in `root.go`
	cmd := &cobra.Command{
		Use:     "scalpel-cli",
		Short:   "Scalpel is an AI-native security scanner.",
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Synchronize logic exactly with cmd/root.go PersistentPreRunE.

			// 1. Initialize configuration loading (Viper)
			if err := initializeConfig(cmd); err != nil {
				// Initialize a basic logger if config loading fails early.
				basicLogger, _ := zap.NewDevelopment()
				defer basicLogger.Sync()
				basicLogger.Error("Failed to initialize configuration", zap.Error(err))
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}

			// 2. Unmarshal the configuration
			var cfg config.Config
			if err := viper.Unmarshal(&cfg); err != nil {
				// Initialize with default logger settings if config is unreadable.
				observability.InitializeLogger(config.LoggerConfig{Level: "info", Format: "console", ServiceName: "scalpel-cli"})
				return fmt.Errorf("failed to unmarshal config: %w", err)
			}

			// 3. Validate the configuration
			if err := cfg.Validate(); err != nil {
				// Initialize logger with what we have to report the validation error.
				observability.InitializeLogger(cfg.Logger)
				return fmt.Errorf("invalid configuration: %w", err)
			}

			// 4. Store the configuration globally
			config.Set(&cfg)

			// 5. Initialize the logger
			observability.InitializeLogger(cfg.Logger)
			// logger := observability.GetLogger()
			// logger.Info("Starting Scalpel-CLI", zap.String("version", Version)) // Omitted in tests usually

			// Handle the validation run flag
			if validateFix {
				// logger.Info("===[ VALIDATION RUN: CONFIGURATION OK ]===")
				// Use cmd.Println() to match root.go and enable test capture.
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
