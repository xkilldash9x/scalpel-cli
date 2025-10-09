// File: cmd/root.go
package cmd

import (
	"context"
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

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:     "scalpel-cli",
	Short:   "Scalpel is an AI-native security scanner.",
	Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
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
		logger := observability.GetLogger()
		logger.Info("Starting Scalpel-CLI", zap.String("version", Version))

		// Handle the validation run flag
		if validateFix {
			logger.Info("===[ VALIDATION RUN: CONFIGURATION OK ]===")
			// A successful validation run should exit cleanly without executing the command.
			cmd.Println("===[ VALIDATION RUN PASSED ]===")
			osExit(0) // Use the mockable exit function
		}

		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// It accepts a context passed from main.go for graceful shutdown.
func Execute(ctx context.Context) error {
	// Add subcommands
	rootCmd.AddCommand(newScanCmd())
	rootCmd.AddCommand(newReportCmd())
	rootCmd.AddCommand(newSelfHealCmd()) // Register the self-heal command
	rootCmd.AddCommand(newEvolveCmd())   // Register the evolve command

	// Execute the root command with the provided context
	if err := rootCmd.ExecuteContext(ctx); err != nil {
		// Handle execution errors gracefully.
		if logger := observability.GetLogger(); logger != nil && logger != zap.NewNop() {
			// Avoid logging context.Canceled errors as failures, as they are expected
			// during graceful shutdown.
			if ctx.Err() == nil {
				logger.Error("Command execution failed", zap.Error(err))
			}
		} else {
			// Fallback if logger isn't initialized yet.
			fmt.Fprintln(os.Stderr, "Error:", err)
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

// initializeConfig reads in config file and ENV variables if set.
func initializeConfig(cmd *cobra.Command) error {
	v := viper.GetViper()

	// 1. Set default values. This is crucial for Viper to know about all possible keys.
	config.SetDefaults(v)

	// 2. Set up environment variable handling.
	v.SetEnvPrefix("SCALPEL")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	v.AutomaticEnv() // This allows Viper to see all env vars that match the prefix.

	// Bind flags to Viper
	if cmd != nil {
		if err := v.BindPFlags(cmd.Flags()); err != nil {
			return fmt.Errorf("failed to bind command flags: %w", err)
		}
		// Also bind persistent flags from the root
		if err := v.BindPFlags(cmd.PersistentFlags()); err != nil {
			return fmt.Errorf("failed to bind persistent command flags: %w", err)
		}
	}

	// 3. Read the configuration file if specified.
	// Values from the file will override the defaults.
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return fmt.Errorf("error reading config file: %w", err)
			}
		}
	}
	// At this point, viper has loaded defaults and the config file.
	// Environment variables found by AutomaticEnv() will have overridden them.
	// We are now certain the configuration is loaded correctly.

	return nil
}
