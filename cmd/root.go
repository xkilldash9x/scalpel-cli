// -- cmd/root.go --
package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap" // Import zap
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

var (
	cfgFile string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "scalpel-cli",
	Short: "Scalpel is an AI-native security scanner.",
    // Version is dynamically set at build time. See cmd/version.go.
    Version: Version,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// This function runs before any command, setting up config and logging.
		if err := initializeConfig(); err != nil {
			return err
		}
		
		var cfg config.Config
		if err := viper.Unmarshal(&cfg); err != nil {
            // Initialize a fallback logger if config unmarshal fails
            observability.InitializeLogger(config.LoggerConfig{Level: "info", Format: "console", ServiceName: "scalpel-cli"})
			return fmt.Errorf("failed to unmarshal config: %w", err)
		}
		
		observability.InitializeLogger(cfg.Logger)

        // Log the version at startup
        observability.GetLogger().Info("Starting Scalpel-CLI", zap.String("version", Version))
		return nil
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
        // Use the logger if available, otherwise fallback to stderr
        if logger := observability.GetLogger(); logger != nil && logger != zap.NewNop() {
             logger.Error("Command execution failed", zap.Error(err))
        } else {
		    fmt.Fprintln(os.Stderr, err)
        }
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ./config.yaml)")
    // Optional: Customize the version output template
    rootCmd.SetVersionTemplate(`{{printf "%s\n" .Version}}`)
}

// initializeConfig reads in config file and ENV variables if set.
func initializeConfig() error {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigName("config")
		viper.SetConfigType("yaml")
	}

	viper.SetEnvPrefix("SCALPEL")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))
	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return fmt.Errorf("error reading config file: %w", err)
		}
        // Config file not found; proceed with defaults/env vars
	}
	return nil
}
