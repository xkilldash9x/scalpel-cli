// File: cmd/self_heal.go
package cmd

import (
	"context"
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/autofix/metalyst"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"go.uber.org/zap"
)

var (
	panicLog     string
	originalArgs []string
)

// newSelfHealCmd creates and returns the self-heal command.
func newSelfHealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "self-heal",
		Short:  "Internal command to orchestrate the self-healing process after a panic.",
		Hidden: true, // This is not a user-facing command
		RunE: func(cmd *cobra.Command, args []string) error {
			// This is the application's REAL entrypoint. It creates the REAL dependencies.
			cfg := config.Get()
			logger := observability.GetLogger()

			// Corrected to use NewClient and pass the agent config.
			llmClient, err := llmclient.NewClient(cfg.Agent, logger)
			if err != nil {
				logger.Error("Failed to initialize LLM client. Self-healing requires a configured LLM.", zap.Error(err))
				return fmt.Errorf("failed to initialize LLM client: %w", err)
			}

			// The initializer for the real Metalyst runner.
			metalystInitFn := func(cfg *config.Config, llm schemas.LLMClient) (MetalystRunner, error) {
				// Corrected to remove the logger argument as per the error signature.
				return metalyst.NewMetalyst(cfg, llm)
			}

			return runSelfHeal(cmd.Context(), cfg, logger, panicLog, originalArgs, llmClient, metalystInitFn)
		},
	}

	cmd.Flags().StringVar(&panicLog, "panic-log", "", "Path to the panic log file.")
	cmd.Flags().StringSliceVar(&originalArgs, "original-args", []string{}, "The original arguments to the command that panicked.")
	_ = cmd.MarkFlagRequired("panic-log")

	return cmd
}

// MetalystRunner defines the interface for the component that runs the healing logic.
type MetalystRunner interface {
	Run(ctx context.Context, panicLogPath string, originalArgs []string) error
}

// MetalystInitializer is a function type for creating a MetalystRunner.
type MetalystInitializer func(*config.Config, schemas.LLMClient) (MetalystRunner, error)

// runSelfHeal contains the testable business logic for the command.
// It now accepts its dependencies as arguments.
func runSelfHeal(
	ctx context.Context,
	cfg *config.Config,
	logger *zap.Logger,
	panicLogPath string,
	args []string,
	llmClient schemas.LLMClient, // Dependency
	initFn MetalystInitializer, // Dependency
) error {
	if panicLogPath == "" {
		return errors.New("--panic-log is required")
	}

	logger.Info(
		"Initiating self-healing process (Metalyst)",
		zap.String("panic_log", panicLogPath),
		zap.Strings("original_args", args),
	)

	runner, err := initFn(cfg, llmClient)
	if err != nil {
		logger.Error("Failed to initialize Metalyst runner", zap.Error(err))
		return fmt.Errorf("failed to initialize Metalyst: %w", err)
	}

	if err := runner.Run(ctx, panicLogPath, args); err != nil {
		logger.Error("Self-healing process failed during execution", zap.Error(err))
		return err
	}

	logger.Info("Self-healing process completed successfully.")
	return nil
}
