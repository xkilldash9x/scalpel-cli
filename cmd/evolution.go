// File: cmd/evolution.go
package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/xkilldash9x/scalpel-cli/api/schemas"
	"github.com/xkilldash9x/scalpel-cli/internal/config"
	"github.com/xkilldash9x/scalpel-cli/internal/evolution/analyst"
	"github.com/xkilldash9x/scalpel-cli/internal/knowledgegraph"
	"github.com/xkilldash9x/scalpel-cli/internal/llmclient"
	"github.com/xkilldash9x/scalpel-cli/internal/observability"
)

// AnalystRunner defines the interface for the component that can execute
// the evolution logic. This abstraction is key for testing.
type AnalystRunner interface {
	Run(ctx context.Context, objective string, files []string) error
}

// analystInitializer is a function type that handles the creation of an
// AnalystRunner. This allows the initialization logic to be injected.
type analystInitializer func(logger *zap.Logger, cfg *config.Config, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error)

// initializeAnalyst provides the default, concrete implementation for creating
// a new ImprovementAnalyst instance.
func initializeAnalyst(logger *zap.Logger, cfg *config.Config, llmClient schemas.LLMClient, kgClient schemas.KnowledgeGraphClient) (AnalystRunner, error) {
	return analyst.NewImprovementAnalyst(logger, cfg, llmClient, kgClient)
}

// newEvolveCmd creates the 'evolve' command.
// It sets up the CLI and delegates execution to the testable runEvolve function.
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
			cfg := config.Get()

			// Initialize the dependencies here, in the "real" entrypoint.
			llmClient, err := llmclient.NewClient(cfg.Agent, logger)
			if err != nil {
				logger.Error("Failed to initialize LLM client. Evolution requires a configured LLM.", zap.Error(err))
				return fmt.Errorf("failed to initialize LLM client: %w", err)
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
	cfg *config.Config,
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

	// 1. Initialize the Knowledge Graph Client (Memory).
	kgClient, cleanup, err := initializeKGClient(ctx, cfg.Agent.KnowledgeGraph, logger, useInMemoryKG)
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

// initializeKGClient connects to the database or starts an in-memory Knowledge Graph.
func initializeKGClient(ctx context.Context, cfg config.KnowledgeGraphConfig, logger *zap.Logger, useInMemory bool) (schemas.KnowledgeGraphClient, func(), error) {
	// Determine if we're falling back to the in-memory graph due to configuration,
	// rather than an explicit command-line flag.
	isInMemoryByDefault := !useInMemory && (cfg.Type == "memory" || cfg.Type == "in-memory" || cfg.Type == "")

	if useInMemory || isInMemoryByDefault {
		// If we are using the in-memory graph because of the config file (and not the explicit flag),
		// log a loud warning that this is not suitable for production.
		if isInMemoryByDefault {
			logger.Warn("No persistent Knowledge Graph configured; defaulting to a temporary in-memory store. All learned data will be lost on exit. This is not recommended for production use.")
		}
		logger.Info("Initializing In-Memory Knowledge Graph.")
		kg, err := knowledgegraph.NewInMemoryKG(logger)
		return kg, nil, err
	}

	if cfg.Type == "postgres" {
		logger.Info("Initializing PostgreSQL Knowledge Graph.", zap.String("host", cfg.Postgres.Host))
		connString := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
			cfg.Postgres.User, cfg.Postgres.Password, cfg.Postgres.Host, cfg.Postgres.Port, cfg.Postgres.DBName, cfg.Postgres.SSLMode)

		poolConfig, err := pgxpool.ParseConfig(connString)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to parse PGX pool config: %w", err)
		}
		poolConfig.MaxConns = 10
		poolConfig.MinConns = 2
		poolConfig.MaxConnLifetime = 1 * time.Hour
		poolConfig.MaxConnIdleTime = 30 * time.Minute

		pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to create PGX connection pool: %w", err)
		}

		if err := pool.Ping(ctx); err != nil {
			pool.Close()
			return nil, nil, fmt.Errorf("failed to ping PostgreSQL: %w", err)
		}

		kg := knowledgegraph.NewPostgresKG(pool, logger)
		cleanup := func() {
			logger.Info("Closing PostgreSQL connection pool.")
			pool.Close()
		}
		return kg, cleanup, nil
	}

	return nil, nil, fmt.Errorf("unsupported Knowledge Graph type: %s", cfg.Type)
}
