// File: cmd/root.go
package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service"
	"go.uber.org/zap"
)

var (
	// osExit allows mocking os.Exit in tests.
	osExit = os.Exit
)

// Define a custom context key to avoid collisions.
type configKeyType struct{}

var configKey = configKeyType{}

// NewRootCommand creates the main entry point for the command-line interface.
// It initializes the root command, sets up persistent flags for configuration,
// configures logging, and attaches all subcommands (like scan, report, etc.).
// This function ensures a clean, state-free command structure for each execution.
func NewRootCommand() *cobra.Command {
	var cfgFile string
	var validateFix bool

	rootCmd := &cobra.Command{
		Use:     "scalpel-cli",
		Short:   "Scalpel is an AI-native security scanner.",
		Version: Version,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			// Create a new, local viper instance for this execution.
			v := viper.New()

			// 1. Initialize configuration loading into our local viper instance.
			if err := initializeConfig(cmd, v, cfgFile); err != nil {
				// Use a basic logger if the main one can't be initialized.
				basicLogger, _ := zap.NewDevelopment()
				defer basicLogger.Sync()
				basicLogger.Error("Failed to initialize configuration", zap.Error(err))
				return fmt.Errorf("failed to initialize configuration: %w", err)
			}

			// 2. Create the config object from viper; this also validates it.
			cfg, err := config.NewConfigFromViper(v)
			if err != nil {
				// Initialize with default logger settings if config is unreadable.
				observability.InitializeLogger(config.LoggerConfig{Level: "info", Format: "console", ServiceName: "scalpel-cli"})
				return fmt.Errorf("failed to load or validate config: %w", err)
			}

			// 3. Initialize the logger using the validated config.
			observability.InitializeLogger(cfg.Logger())
			logger := observability.GetLogger()
			logger.Info("Starting Scalpel-CLI", zap.String("version", Version))

			// 4. Store the validated config in the command's context for subcommands.
			ctx := context.WithValue(cmd.Context(), configKey, cfg)
			cmd.SetContext(ctx)

			// Handle the validation run flag
			if validateFix {
				logger.Info("===[ VALIDATION RUN: CONFIGURATION OK ]===")
				cmd.Println("===[ VALIDATION RUN PASSED ]===")
				osExit(0)
			}

			return nil
		},
	}

	// --- Flag Definitions ---
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&validateFix, "validate-fix", false, "Internal flag for self-healing validation.")
	_ = rootCmd.PersistentFlags().MarkHidden("validate-fix")

	// --- Sub-command Initialization ---
	// Use the centralized service factory.
	componentFactory := service.NewComponentFactory()
	storeProvider := NewStoreProvider()

	rootCmd.AddCommand(newScanCmd(componentFactory))
	rootCmd.AddCommand(newReportCmd(storeProvider))
	rootCmd.AddCommand(newSelfHealCmd())
	rootCmd.AddCommand(newEvolveCmd())

	return rootCmd
}

// Execute is the primary entry point for the Scalpel CLI application. It creates a
// new root command, executes it with the provided context, and handles top-level
// error logging. If the context is canceled (e.g., by Ctrl+C), it suppresses
// redundant error messages for a cleaner user experience.
func Execute(ctx context.Context) error {
	cmd := NewRootCommand()

	if err := cmd.ExecuteContext(ctx); err != nil {
		logger := observability.GetLogger()
		// Only log the error if the context wasn't canceled (i.e., not a Ctrl+C).
		// This avoids redundant error messages on graceful shutdown.
		if !errors.Is(ctx.Err(), context.Canceled) {
			if logger != nil && logger != zap.NewNop() {
				logger.Error("Command execution failed", zap.Error(err))
			} else {
				// Fallback if the logger wasn't initialized.
				fmt.Fprintln(os.Stderr, "Error:", err)
			}
		}
		return err
	}
	return nil
}

// initializeConfig sets up and loads configuration into the provided viper instance.
func initializeConfig(cmd *cobra.Command, v *viper.Viper, cfgFile string) error {
	// 1. Set default values.
	config.SetDefaults(v)

	// 2. Set up environment variable handling.
	v.SetEnvPrefix("SCALPEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv()

	// 3. Bind cobra flags to Viper.
	if cmd != nil {
		if err := v.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("failed to bind command flags: %w", err)
		}
		if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
			return fmt.Errorf("failed to bind persistent command flags: %w", err)
		}
	}

	// 4. Read the configuration file if specified.
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			// It's okay if the file is not found, but any other error is a problem.
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return fmt.Errorf("error reading config file: %w", err)
			}
		}
	}

	return nil
}

// getConfigFromContext is a helper function for subcommands to retrieve the config.
func getConfigFromContext(ctx context.Context) (config.Interface, error) {
	if cfg, ok := ctx.Value(configKey).(config.Interface); ok && cfg != nil {
		return cfg, nil
	}
	return nil, fmt.Errorf("configuration not found in context; this indicates a bug in command setup")
}
