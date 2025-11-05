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
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service"
	"go.uber.org/zap"
)

// newSelfHealCmd creates and returns the self-heal command.
func newSelfHealCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:    "self-heal",
		Short:  "Internal command to orchestrate the self-healing process after a panic.",
		Hidden: true, // This is not a user-facing command
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := observability.GetLogger()

			// Get the config from the context.
			cfg, err := getConfigFromContext(ctx)
			if err != nil {
				return err
			}

			panicLog, _ := cmd.Flags().GetString("panic-log")
			originalArgs, _ := cmd.Flags().GetStringSlice("original-args")

			// Initialize the LLM client using the centralized initializer.
			llmClient, err := service.InitializeLLMClient(logger, cfg.Agent())
			if err != nil {
				return err // Error is already logged and formatted by the initializer
			}

			// The initializer for the real Metalyst runner.
			metalystInitFn := func(logger *zap.Logger, cfg config.Interface, llm schemas.LLMClient) (MetalystRunner, error) {
				// Safely perform the type assertion.
				concreteCfg, ok := cfg.(*config.Config)
				if !ok {
					return nil, errors.New("metalyst runner requires a concrete *config.Config implementation")
				}
				return metalyst.NewMetalyst(logger, concreteCfg, llm)
			}

			return runSelfHeal(ctx, cfg, logger, panicLog, originalArgs, llmClient, metalystInitFn)
		},
	}

	cmd.Flags().String("panic-log", "", "Path to the panic log file.")
	cmd.Flags().StringSlice("original-args", []string{}, "The original arguments to the command that panicked.")

	_ = cmd.MarkFlagRequired("panic-log")
	return cmd
}

// MetalystRunner defines the interface for the component that runs the healing logic.
type MetalystRunner interface {
	Run(ctx context.Context, panicLogPath string, originalArgs []string) error
}

// MetalystInitializer is a function type for creating a MetalystRunner.
type MetalystInitializer func(*zap.Logger, config.Interface, schemas.LLMClient) (MetalystRunner, error)

// runSelfHeal contains the testable business logic for the command.
func runSelfHeal(
	ctx context.Context,
	cfg config.Interface,
	logger *zap.Logger,
	panicLogPath string,
	args []string,
	llmClient schemas.LLMClient,
	initFn MetalystInitializer,
) error {
	if panicLogPath == "" {
		return errors.New("--panic-log is required")
	}

	logger.Info(
		"Initiating self-healing process (Metalyst)",
		zap.String("panic_log", panicLogPath),
		zap.Strings("original_args", args),
	)

	runner, err := initFn(logger, cfg, llmClient)
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
