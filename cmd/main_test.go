// File: cmd/main_test.go
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service" // FIX: Import the service package
	"go.uber.org/zap"
)

// newPristineRootCmd creates a completely new instance of the rootCmd,
// mirroring the setup in root.go to ensure test isolation.
func newPristineRootCmd() *cobra.Command {
	// FIX: Declare variables for flags to match the scope in root.go
	var cfgFile string
	var validateFix bool

	// This function body mirrors the initialization logic typically found in root.go.
	cmd := &cobra.Command{
		Use:     "scalpel-cli",
		Short:   "Scalpel is an AI-native security scanner.",
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			v := viper.New()

			// 1. Initialize configuration loading
			// FIX: Pass the 'cfgFile' variable to match the function's signature.
			if err := initializeConfig(cmd, v, cfgFile); err != nil {
				basicLogger, _ := zap.NewDevelopment()
				defer basicLogger.Sync()
				basicLogger.Error("Failed to initialize configuration", zap.Error(err))
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}

			// 2. Create the configuration object from viper.
			cfg, err := config.NewConfigFromViper(v)
			if err != nil {
				observability.InitializeLogger(config.LoggerConfig{Level: "info", Format: "console", ServiceName: "scalpel-cli"})
				return fmt.Errorf("failed to load or validate config: %w", err)
			}

			// 3. Initialize the logger with the loaded config.
			observability.InitializeLogger(cfg.Logger())
			logger := observability.GetLogger()
			logger.Info("Starting Scalpel-CLI", zap.String("version", Version))

			// 4. Store the validated config in the command's context.
			ctx := context.WithValue(cmd.Context(), configKey, cfg)
			cmd.SetContext(ctx)

			// 5. Handle the validation run flag
			if validateFix {
				cmd.Println("===[ VALIDATION RUN PASSED ]===")
				osExit(0)
			}
			return nil
		},
	}
	// Initialize persistent flags. These now have variables to bind to.
	cmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
	cmd.PersistentFlags().BoolVar(&validateFix, "validate-fix", false, "Internal flag for self-healing validation.")
	_ = cmd.PersistentFlags().MarkHidden("validate-fix")

	// Re-attach subcommands, providing their required dependencies.
	// FIX: Use the service package's ComponentFactory, just like in cmd/root.go
	cmd.AddCommand(newScanCmd(service.NewComponentFactory()))
	cmd.AddCommand(newReportCmd(NewStoreProvider()))

	// Assuming these commands exist and are correctly defined elsewhere in the cmd package.
	cmd.AddCommand(newSelfHealCmd())
	cmd.AddCommand(newEvolveCmd())
	return cmd
}
