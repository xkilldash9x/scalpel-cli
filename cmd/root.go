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
	"go.uber.org/zap"
)

var (
	cfgFile     string
	validateFix bool // Flag for validation runs during self-healing
	// osExit allows mocking os.Exit in tests.
	osExit = os.Exit
)

// Define a custom context key to avoid collisions.
type configKeyType struct{}

var configKey = configKeyType{}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "scalpel-cli",
	Short:   "Scalpel is an AI-native security scanner.",
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// Create a new, local viper instance for this execution.
		v := viper.New()

		// 1. Initialize configuration loading into our local viper instance.
		if err := initializeConfig(cmd, v); err != nil {
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

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute(ctx context.Context) error {
	// Initialize the component factories/providers for production.
	componentFactory := NewComponentFactory()
	storeProvider := NewStoreProvider()

	// Inject the dependencies into their respective commands.
	rootCmd.AddCommand(newScanCmd(componentFactory))
	rootCmd.AddCommand(newReportCmd(storeProvider))
	rootCmd.AddCommand(newSelfHealCmd())
	rootCmd.AddCommand(newEvolveCmd())

	if err := rootCmd.ExecuteContext(ctx); err != nil {
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

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
	rootCmd.PersistentFlags().BoolVar(&validateFix, "validate-fix", false, "Internal flag for self-healing validation.")
	_ = rootCmd.PersistentFlags().MarkHidden("validate-fix")
}

// initializeConfig sets up and loads configuration into the provided viper instance.
func initializeConfig(cmd *cobra.Command, v *viper.Viper) error {
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
