// File: cmd/evolution.go
package cmd

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/analyst"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
	"github.com/xkilldash9x/scalpel-cli/internal/service"
)

// AnalystRunner defines the interface for a component capable of executing the main
// evolution logic. Using an interface allows for decoupling and easier testing
// by enabling mock implementations.
type AnalystRunner interface {
	// Run starts the evolution process with a given high-level objective and an
	// optional set of initial files for context.
	Run(ctx context.Context, objective string, files []string) error
}

// analystInitializer is a function signature for creating an AnalystRunner.
// This allows for dependency injection of the analyst's initialization logic,
// primarily for testing purposes.
type analystInitializer func(logger *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error)

// initializeAnalyst is the default implementation of analystInitializer. It creates
// a new instance of the concrete ImprovementAnalyst from the 'analyst' package.
func initializeAnalyst(logger *zap.Logger, cfg config.Interface, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
	return analyst.NewImprovementAnalyst(logger, cfg, llmClient, kgClient)
}

// newEvolveCmd creates the 'evolve' command for the CLI. This command
// initiates the autonomous self-improvement process (Reflective OODA Loop)
// for the codebase. It is responsible for parsing command-line flags and
// setting up the necessary dependencies before delegating the core logic to
// runEvolve.
func newEvolveCmd() *cobra.Command {
	var objective string
	var files []string
	var useInMemoryKG bool

	// Use the default initializer for the application's runtime.
	initFn := initializeAnalyst

	cmd := &cobra.Command{
		Use:   "evolve --objective <description>",
		Short: "Initiates the autonomous self-improvement process (Reflective OODA Loop).",
		Long: `The evolve command starts the Reflective OODA loop to proactively improve the codebase
based on a high-level objective, learning from past attempts.
WARNING: This process modifies the local codebase. Ensure your working directory is clean.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			logger := observability.GetLogger()
			cfg, err := getConfigFromContext(ctx)
			if err != nil {
				return err // Error is already descriptive
			}

			// Initialize the LLM client using the centralized initializer.
			llmClient, err := service.InitializeLLMClient(ctx, cfg.Agent(), logger)
			if err != nil {
				return err // Error is already logged and formatted by the initializer
			}

			// Delegate the core logic to a separate, testable function.
			return runEvolve(ctx, cfg, logger, objective, files, useInMemoryKG, llmClient, initFn)
		},
	}

	cmd.Flags().StringVarP(&objective, "objective", "o", "", "The high-level improvement goal (required).")
	cmd.Flags().StringSliceVarP(&files, "files", "f", []string{}, "Relevant files for initial context (comma-separated).")
	cmd.Flags().BoolVar(&useInMemoryKG, "mem-kg", false, "Use in-memory Knowledge Graph instead of PostgreSQL (data is lost on exit).")
	_ = cmd.MarkFlagRequired("objective")

	return cmd
}

// runEvolve contains the core application logic for the evolution process.
// It is decoupled from cobra and accepts all dependencies as arguments.
func runEvolve(
	ctx context.Context,
	cfg config.Interface,
	logger *zap.Logger,
	objective string,
	files []string,
	useInMemoryKG bool,
	llmClient schemas.LLMClient, // Dependency is now injected
	initFn analystInitializer,
) error {
	if objective == "" {
		return fmt.Errorf("--objective is required")
	}

	// 1. Initialize the Knowledge Graph Client using the centralized initializer.
	kgClient, cleanup, err := service.InitializeKGClient(ctx, cfg.Agent().KnowledgeGraph, logger, useInMemoryKG)
	if err != nil {
		logger.Error("Failed to initialize Knowledge Graph client.", zap.Error(err))
		return fmt.Errorf("failed to initialize KG client: %w", err)
	}
	if cleanup != nil {
		defer cleanup()
	}

	// 2. Initialize the Improvement Analyst using the injected initializer.
	ia, err := initFn(logger, cfg, llmClient, kgClient)
	if err != nil {
		return fmt.Errorf("failed to initialize Improvement Analyst: %w", err)
	}

	logger.Info("Starting Evolution process (Reflective OODA Loop).", zap.String("objective", objective))
	if err := ia.Run(ctx, objective, files); err != nil {
		logger.Error("Evolution process finished with error.", zap.Error(err))
		return fmt.Errorf("evolution process error: %w", err)
	}

	logger.Info("Evolution process completed successfully.")
	return nil
}
